/**
 * The app's background: a secure network, matching the website
 * (static/net_background.js). A fine grid with circuit traces covers the
 * whole screen; its nodes glint softly one after another, and now and then a
 * data packet glides along a trace, easing in and out, and the node it
 * reaches answers with a soft ring. Now and then a packet is a threat,
 * stopped with a red ring.
 *
 * The grid is one small repeated image; the traces are drawn once after the
 * screen transition and kept as a texture; packets are plain views moved with
 * transforms on the UI thread from one clock (useFrameCallback, ~30 fps), so
 * nothing is redrawn while they move. The clock stops when the screen is not
 * focused, and the network is still for people who turn on Reduce motion.
 */
import { useIsFocused } from 'expo-router';
import { LinearGradient } from 'expo-linear-gradient';
import { memo, useEffect, useMemo, useState } from 'react';
import { Image, InteractionManager, StyleSheet, useWindowDimensions, View } from 'react-native';
import Animated, { FadeIn, useAnimatedStyle, useFrameCallback, useReducedMotion, useSharedValue, type SharedValue } from 'react-native-reanimated';
import Svg, { Path } from 'react-native-svg';
import { scheduleOnRN } from 'react-native-worklets';

import { Glow } from '@/components/motion';
import { updateSettings, useSettings } from '@/lib/settings';


const CELL = 34;
const CYAN = '#77dcff';
const TEAL = '#5eead4';
const RED = '#fb7185';
const GRID_TILE = require('../../assets/images/grid-tile.png');
const GLINT = 7;
// Frame pacing check: after WARMUP seconds of motion, measure SAMPLE seconds; slower than
// SLOW seconds a frame on average (under ~40 fps) means the phone struggles, so the motion
// is turned off for good (Settings › Animated background turns it back on).
const WARMUP = 2, SAMPLE = 3, SLOW = 1 / 40;

function slowPhone() {
  updateSettings({ backgroundMotion: false, motionChecked: true });
}

function smoothPhone() {
  updateSettings({ motionChecked: true });
}    // seconds between two glints of the same node
const TAIL = 40;
const HEAD = 4;
const ARRIVE = 1.6; // seconds the arrival ring plays

type Route = { xs: number[]; ys: number[]; lengths: number[]; total: number };
type Packet = { route: Route; travel: number; period: number; offset: number; color: string; threat: boolean };

/** A small seeded random generator, so the network keeps its shape between renders. */
function seeded(seed: number) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function buildNetwork(width: number, height: number) {
  const random = seeded(Math.round(width) * 31 + Math.round(height));
  const cols = Math.ceil(width / CELL);
  const rows = Math.ceil(height / CELL);

  const routes: Route[] = [];
  while (routes.length < 7) {
    // An orthogonal trace, like a circuit board; each in its own slice of the screen so they spread out.
    const low = Math.floor((routes.length / 7) * rows), high = Math.min(rows, Math.ceil(((routes.length + 1) / 7) * rows) + 2);
    let x = Math.floor(random() * (cols + 1));
    let y = low + Math.floor(random() * (high - low + 1));
    const xs = [x * CELL], ys = [y * CELL];
    let horizontal = random() < 0.6;
    const turns = 2 + Math.floor(random() * 2);
    for (let i = 0; i < turns; i++) {
      const step = (random() < 0.5 ? -1 : 1) * (2 + Math.floor(random() * 4));
      if (horizontal) x = Math.max(0, Math.min(cols, x + step)); else y = Math.max(0, Math.min(rows, y + step));
      if (xs[xs.length - 1] !== x * CELL || ys[ys.length - 1] !== y * CELL) { xs.push(x * CELL); ys.push(y * CELL); }
      horizontal = !horizontal;
    }
    const lengths = [0];
    for (let i = 1; i < xs.length; i++) lengths.push(lengths[i - 1] + Math.abs(xs[i] - xs[i - 1]) + Math.abs(ys[i] - ys[i - 1]));
    const total = lengths[lengths.length - 1];
    if (total > CELL * 4) routes.push({ xs, ys, lengths, total });
  }
  const traces = routes.map((r) => r.xs.map((x, i) => `${i ? 'L' : 'M'}${x} ${r.ys[i]}`).join('')).join('');
  const nodes = routes.map((r) => {
    const end = r.xs.length - 1;
    return `M${r.xs[0] - 1.2} ${r.ys[0] - 1.2}h2.4v2.4h-2.4zM${r.xs[end] - 1.8} ${r.ys[end] - 1.8}h3.6v3.6h-3.6z`;
  }).join('');
  // Nodes that glint: both ends of every trace, each at its own moment.
  const glints = routes.flatMap((r, i) => [[r.xs[0], r.ys[0]], [r.xs[r.xs.length - 1], r.ys[r.ys.length - 1]]]
    .map(([x, y], k) => ({ x, y, offset: ((i * 2 + k) * 0.618 % 1) * GLINT })));
  const packets: Packet[] = routes.slice(0, 5).map((route, i) => {
    const threat = i === 3;
    const travel = route.total / (42 + random() * 22);
    // The threat comes round less often than the others, so red stays a rare moment.
    const period = travel + ARRIVE + 3 + random() * 5 + (threat ? 9 : 0);
    // Spread the start times so one or two packets are moving at any moment.
    return { route, threat, travel, period, offset: (i / 5) * period + random() * 1.5,
             color: threat ? RED : i % 2 ? TEAL : CYAN };
  });
  return { traces, nodes, routes, packets, glints };
}

type Network = ReturnType<typeof buildNetwork>;
// Every screen has the same size, so they share one network instead of each building its own.
const networks = new Map<string, Network>();
function networkFor(width: number, height: number) {
  const key = `${Math.round(width)}x${Math.round(height)}`;
  if (!networks.has(key)) networks.set(key, buildNetwork(width, height));
  return networks.get(key)!;
}

function point(route: Route, distance: number): [number, number] {
  'worklet';
  const d = Math.max(0, Math.min(route.total, distance));
  let i = 1;
  while (i < route.lengths.length - 1 && route.lengths[i] < d) i++;
  const span = route.lengths[i] - route.lengths[i - 1] || 1;
  const f = (d - route.lengths[i - 1]) / span;
  return [route.xs[i - 1] + (route.xs[i] - route.xs[i - 1]) * f, route.ys[i - 1] + (route.ys[i] - route.ys[i - 1]) * f];
}

/** Seconds into this packet's own cycle: gliding while < travel, then its arrival ring, then rest. */
function local(p: Packet, time: number) {
  'worklet';
  return (time + p.offset) % p.period;
}

/** How far along the route, eased so the packet sets off and arrives gently; and how fast, 0..1. */
function glide(p: Packet, t: number) {
  'worklet';
  const k = t / p.travel;
  return { d: p.route.total * (0.5 - 0.5 * Math.cos(Math.PI * k)), pace: Math.sin(Math.PI * k) };
}

/**
 * One data packet. Everything here animates transform and opacity only, so the
 * GPU moves it without redrawing anything; the grid underneath is drawn once.
 */
function DataPacket({ p, clock }: { p: Packet; clock: SharedValue<number> }) {
  const head = useAnimatedStyle(() => {
    const t = local(p, clock.value);
    if (t >= p.travel + 0.4) return { opacity: 0 };
    const [x, y] = point(p.route, glide(p, Math.min(t, p.travel)).d);
    const opacity = t < p.travel ? Math.min(1, t / 0.7) : 1 - (t - p.travel) / 0.4;
    return { opacity, transform: [{ translateX: x }, { translateY: y }] };
  });
  // A soft comet tail that stretches with speed and turns with the trace.
  const tail = useAnimatedStyle(() => {
    const t = local(p, clock.value);
    if (t >= p.travel) return { opacity: 0 };
    const { d, pace } = glide(p, t);
    const [x, y] = point(p.route, d);
    const [bx, by] = point(p.route, d - 1.5);
    const angle = Math.abs(x - bx) >= Math.abs(y - by) ? (x >= bx ? 0 : 180) : (y >= by ? 90 : -90);
    const length = Math.min(TAIL * (0.2 + 0.8 * pace), d);
    return { opacity: Math.min(1, t / 0.7) * 0.8,
             transform: [{ translateX: x - TAIL }, { translateY: y - 1 }, { rotate: `${angle}deg` }, { scaleX: Math.max(0.01, length / TAIL) }] };
  });
  const end = p.route.xs.length - 1;
  const size = p.threat ? 34 : 26;
  const ring = useAnimatedStyle(() => {
    const t = local(p, clock.value) - p.travel;
    if (t < 0 || t > ARRIVE) return { opacity: 0 };
    const k = t / ARRIVE;
    const eased = 1 - (1 - k) * (1 - k);
    return { opacity: (p.threat ? 0.7 : 0.4) * (1 - k), transform: [{ scale: 0.2 + 0.8 * eased }] };
  });
  return (
    <>
      <Animated.View style={[st.at, { width: TAIL, height: 2, transformOrigin: 'right' }, tail]}>
        <LinearGradient colors={[`${p.color}00`, `${p.color}aa`]} start={{ x: 0, y: 0.5 }} end={{ x: 1, y: 0.5 }} style={StyleSheet.absoluteFill} />
      </Animated.View>
      <Animated.View style={[st.at, head]}>
        <View style={[st.halo, { backgroundColor: p.color }]} />
        <View style={[st.head, { backgroundColor: p.color, shadowColor: p.color }]} />
      </Animated.View>
      <Animated.View style={[st.at, { left: p.route.xs[end] - size / 2, top: p.route.ys[end] - size / 2, width: size, height: size,
        borderRadius: size / 2, borderWidth: 1, borderColor: p.color }, ring]} />
    </>
  );
}

/** A node that brightens for a moment and fades, like light catching it. */
function Glint({ g, clock }: { g: { x: number; y: number; offset: number }; clock: SharedValue<number> }) {
  const style = useAnimatedStyle(() => {
    const k = ((clock.value + g.offset) % GLINT) / 1.6;
    const v = k < 1 ? Math.sin(Math.PI * k) : 0;
    return { opacity: v * 0.9, transform: [{ scale: 0.6 + 0.4 * v }] };
  });
  return (
    <Animated.View style={[st.at, { left: g.x, top: g.y }, style]}>
      <View style={[st.halo, { backgroundColor: CYAN }]} />
      <View style={[st.head, { backgroundColor: '#c9f3ff', shadowColor: CYAN }]} />
    </Animated.View>
  );
}

/** The grid: one small tile repeated by the image view, so a new screen costs almost nothing to draw. */
const Grid = memo(function Grid({ width, height }: { width: number; height: number }) {
  // An explicit size: an image otherwise takes its own (the tile's) size on some platforms.
  return <Image source={GRID_TILE} resizeMode="repeat" style={{ position: 'absolute', left: 0, top: 0, width, height }} />;
});

/** Traces and nodes: drawn once and kept as a texture, never redrawn by the animation. */
const Traces = memo(function Traces({ width, height, net }: { width: number; height: number; net: Network }) {
  return (
    <Animated.View entering={FadeIn.duration(500)} style={StyleSheet.absoluteFill} renderToHardwareTextureAndroid shouldRasterizeIOS>
      <Svg width={width} height={height}>
        <Path d={net.traces} stroke={CYAN} strokeOpacity={0.15} strokeWidth={1.1} fill="none" />
        <Path d={net.nodes} fill={CYAN} fillOpacity={0.5} />
      </Svg>
    </Animated.View>
  );
});

/** The background for a screen inside the navigator: it moves only while the screen is in front. */
export function NetworkBackground() {
  return <NetworkLayer focused={useIsFocused()} />;
}

/** The background itself; outside the navigator (the update screen) pass focused yourself. */
export function NetworkLayer({ focused }: { focused: boolean }) {
  const { width, height } = useWindowDimensions();
  const reduced = useReducedMotion();
  const net = useMemo(() => networkFor(width, height), [width, height]);
  const { backgroundMotion, motionChecked } = useSettings();
  const clock = useSharedValue(0);
  const lastTick = useSharedValue(0);
  const watched = useSharedValue(motionChecked ? -1 : 0);  // seconds measured so far; -1 once decided
  const frames = useSharedValue(0);
  const frame = useFrameCallback((info) => {
    // About 30 updates a second is smooth for slow-moving packets and halves the work.
    const step = (info.timeSincePreviousFrame ?? 16) / 1000;
    lastTick.value += step;
    if (lastTick.value >= 0.032) { clock.value += lastTick.value; lastTick.value = 0; }
    if (watched.value < 0) return;
    watched.value += step;
    if (watched.value > WARMUP) frames.value += 1;
    if (watched.value >= WARMUP + SAMPLE) {
      const average = SAMPLE / Math.max(1, frames.value);
      watched.value = -1;
      scheduleOnRN(average > SLOW ? slowPhone : smoothPhone);
    }
  }, false);
  // The traces and the motion wait until the screen transition has finished, so the two never compete;
  // during the slide only the gradient and the grid tile are drawn.
  const [settled, setSettled] = useState(false);
  useEffect(() => {
    const task = InteractionManager.runAfterInteractions(() => setSettled(true));
    return () => task.cancel();
  }, []);
  const moving = focused && !reduced && settled && backgroundMotion;
  useEffect(() => { frame.setActive(moving); }, [frame, moving]);

  return (
    <View pointerEvents="none" style={StyleSheet.absoluteFill}>
      <LinearGradient colors={['#04080f', '#071321', '#050a12']} style={StyleSheet.absoluteFill} />
      <View style={{ position: 'absolute', top: -170, left: -110 }}><Glow size={440} color="#1f7fb3" opacity={0.22} /></View>
      <Grid width={width} height={height} />
      {settled ? <Traces width={width} height={height} net={net} /> : null}
      {moving ? net.glints.map((g, i) => <Glint key={`g${i}`} g={g} clock={clock} />) : null}
      {moving ? net.packets.map((p, i) => <DataPacket key={i} p={p} clock={clock} />) : null}
    </View>
  );
}

const st = StyleSheet.create({
  at: { position: 'absolute', left: 0, top: 0 },
  halo: { position: 'absolute', left: -7, top: -7, width: 14, height: 14, borderRadius: 7, opacity: 0.16 },
  head: { position: 'absolute', left: -HEAD / 2, top: -HEAD / 2, width: HEAD, height: HEAD, borderRadius: HEAD / 2,
          shadowOpacity: 0.9, shadowRadius: 4, shadowOffset: { width: 0, height: 0 } },
});
