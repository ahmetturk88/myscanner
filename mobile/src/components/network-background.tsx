/**
 * The app's background: a quiet secure network, matching the website
 * (static/net_background.js). A faint dot grid with a few circuit traces near
 * the top and bottom of the screen; now and then a data packet glides along
 * one, easing in and out, and the node it reaches answers with a soft ring.
 * One packet in five is a threat, stopped with a red ring. A slow, faint scan
 * line passes every so often. The middle of the screen, where the text is,
 * stays calm.
 *
 * The grid is drawn once and kept as a texture; packets are plain views moved
 * with transforms on the UI thread from one clock (useFrameCallback, ~30 fps),
 * so nothing is redrawn while they move. The clock starts after the screen
 * transition, stops when the screen is not focused, and the network is still
 * for people who turn on Reduce motion.
 */
import { useIsFocused } from 'expo-router';
import { LinearGradient } from 'expo-linear-gradient';
import { memo, useEffect, useMemo, useState } from 'react';
import { InteractionManager, StyleSheet, useWindowDimensions, View } from 'react-native';
import Animated, { useAnimatedStyle, useFrameCallback, useReducedMotion, useSharedValue, type SharedValue } from 'react-native-reanimated';
import Svg, { Path } from 'react-native-svg';

import { Glow } from '@/components/motion';


const CELL = 34;
const CYAN = '#77dcff';
const TEAL = '#5eead4';
const RED = '#fb7185';
const BG = '5,10,18';
const SWEEP = 9;   // seconds the scan line takes to cross the screen
const CYCLE = 22;  // seconds between sweeps
const BEAM = 90;
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
  // Dots at the grid crossings, not lines: structure without stripes behind the text.
  let dots = '';
  for (let i = 1; i < rows; i++) for (let j = 1; j < cols; j++) dots += `M${j * CELL} ${i * CELL}h0.01`;

  const routes: Route[] = [];
  const band = Math.max(3, Math.floor(rows * 0.3));
  while (routes.length < 5) {
    // An orthogonal trace in the top or bottom band, like a circuit board.
    const top = routes.length % 2 === 0;
    const low = top ? 0 : rows - band, high = top ? band : rows;
    let x = Math.floor(random() * (cols + 1));
    let y = low + Math.floor(random() * (high - low + 1));
    const xs = [x * CELL], ys = [y * CELL];
    let horizontal = random() < 0.6;
    const turns = 2 + Math.floor(random() * 2);
    for (let i = 0; i < turns; i++) {
      const step = (random() < 0.5 ? -1 : 1) * (2 + Math.floor(random() * 4));
      if (horizontal) x = Math.max(0, Math.min(cols, x + step)); else y = Math.max(low, Math.min(high, y + step));
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
  const packets: Packet[] = routes.map((route, i) => {
    const threat = i === 3;
    const travel = route.total / (42 + random() * 22);
    // The threat comes round less often than the others, so red stays a rare moment.
    const period = travel + ARRIVE + 3 + random() * 5 + (threat ? 9 : 0);
    // Spread the start times so one or two packets are moving at any moment.
    return { route, threat, travel, period, offset: (i / routes.length) * period + random() * 1.5,
             color: threat ? RED : i % 2 ? TEAL : CYAN };
  });
  return { dots, traces, nodes, routes, packets };
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

/** Dots, traces and nodes: drawn once and kept as a texture, never redrawn by the animation. */
const StaticNetwork = memo(function StaticNetwork({ width, height, net }: { width: number; height: number; net: ReturnType<typeof buildNetwork> }) {
  return (
    <View style={StyleSheet.absoluteFill} renderToHardwareTextureAndroid shouldRasterizeIOS>
      <Svg width={width} height={height}>
        <Path d={net.dots} stroke={CYAN} strokeOpacity={0.11} strokeWidth={1.4} strokeLinecap="round" />
        <Path d={net.traces} stroke={CYAN} strokeOpacity={0.09} strokeWidth={1} fill="none" />
        <Path d={net.nodes} fill={CYAN} fillOpacity={0.4} />
      </Svg>
    </View>
  );
});

export function NetworkBackground() {
  const { width, height } = useWindowDimensions();
  const focused = useIsFocused();
  const reduced = useReducedMotion();
  const net = useMemo(() => buildNetwork(width, height), [width, height]);
  const clock = useSharedValue(0);
  const lastTick = useSharedValue(0);
  const frame = useFrameCallback((info) => {
    // About 30 updates a second is smooth for slow-moving packets and halves the work.
    const step = (info.timeSincePreviousFrame ?? 16) / 1000;
    lastTick.value += step;
    if (lastTick.value >= 0.032) { clock.value += lastTick.value; lastTick.value = 0; }
  }, false);
  // Start only once the screen transition has finished, so the two never compete.
  const [settled, setSettled] = useState(false);
  useEffect(() => {
    const task = InteractionManager.runAfterInteractions(() => setSettled(true));
    return () => task.cancel();
  }, []);
  const moving = focused && !reduced && settled;
  useEffect(() => { frame.setActive(moving); }, [frame, moving]);

  const beam = useAnimatedStyle(() => {
    const t = (clock.value + 6) % CYCLE;
    if (t >= SWEEP) return { opacity: 0 };
    const k = t / SWEEP;
    // Fades in at the top and out at the bottom, so it never pops.
    return { opacity: Math.min(1, k * 6, (1 - k) * 6), transform: [{ translateY: -BEAM + (height + BEAM) * k }] };
  });

  return (
    <View pointerEvents="none" style={StyleSheet.absoluteFill}>
      <LinearGradient colors={['#04080f', '#071321', '#050a12']} style={StyleSheet.absoluteFill} />
      <View style={{ position: 'absolute', top: -170, left: -110 }}><Glow size={440} color="#1f7fb3" opacity={0.22} /></View>
      <StaticNetwork width={width} height={height} net={net} />
      {moving ? net.packets.map((p, i) => <DataPacket key={i} p={p} clock={clock} />) : null}
      {moving ? (
        <Animated.View style={[{ position: 'absolute', left: 0, right: 0, height: BEAM }, beam]}>
          <LinearGradient colors={['rgba(119,220,255,0)', 'rgba(119,220,255,0.035)']} style={StyleSheet.absoluteFill} />
          <View style={{ position: 'absolute', left: 0, right: 0, bottom: 0, height: 1, backgroundColor: 'rgba(119,220,255,0.16)' }} />
        </Animated.View>
      ) : null}
      {/* A soft veil over the middle, so the text there reads on a calm background. */}
      <LinearGradient colors={[`rgba(${BG},0)`, `rgba(${BG},0.6)`, `rgba(${BG},0.6)`, `rgba(${BG},0)`]}
        locations={[0.2, 0.38, 0.62, 0.8]} style={StyleSheet.absoluteFill} />
    </View>
  );
}

const st = StyleSheet.create({
  at: { position: 'absolute', left: 0, top: 0 },
  halo: { position: 'absolute', left: -7, top: -7, width: 14, height: 14, borderRadius: 7, opacity: 0.16 },
  head: { position: 'absolute', left: -HEAD / 2, top: -HEAD / 2, width: HEAD, height: HEAD, borderRadius: HEAD / 2,
          shadowOpacity: 0.9, shadowRadius: 4, shadowOffset: { width: 0, height: 0 } },
});
