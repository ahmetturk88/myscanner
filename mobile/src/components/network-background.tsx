/**
 * The app's background: a secure data network, matching the website
 * (static/net_background.js). Circuit-like traces on a fine grid carry data
 * packets between nodes, a scan beam sweeps down the screen, and now and then
 * a red packet is stopped at a checkpoint node.
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
import Svg, { Path, Rect } from 'react-native-svg';

import { Glow } from '@/components/motion';


const CELL = 34;
const CYAN = '#77dcff';
const TEAL = '#5eead4';
const RED = '#fb7185';
const SWEEP = 6;   // seconds the scan beam takes to cross the screen
const CYCLE = 11;  // seconds between sweeps
const BEAM = 150;

type Route = { xs: number[]; ys: number[]; lengths: number[]; total: number };
type Packet = { route: Route; speed: number; offset: number; color: string; threat: boolean; tail: number };

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
  let grid = '';
  for (let i = 0; i <= rows; i++) grid += `M0 ${i * CELL}H${width}`;
  for (let j = 0; j <= cols; j++) grid += `M${j * CELL} 0V${height}`;

  const routes: Route[] = [];
  while (routes.length < 8) {
    // An orthogonal trace: alternating horizontal and vertical runs, like a circuit board.
    let x = Math.floor(random() * (cols + 1));
    let y = Math.floor(random() * (rows + 1));
    const xs = [x * CELL], ys = [y * CELL];
    let horizontal = random() < 0.5;
    const turns = 2 + Math.floor(random() * 3);
    for (let i = 0; i < turns; i++) {
      const step = (random() < 0.5 ? -1 : 1) * (2 + Math.floor(random() * 5));
      if (horizontal) x = Math.max(0, Math.min(cols, x + step)); else y = Math.max(0, Math.min(rows, y + step));
      if (xs[xs.length - 1] !== x * CELL || ys[ys.length - 1] !== y * CELL) { xs.push(x * CELL); ys.push(y * CELL); }
      horizontal = !horizontal;
    }
    const lengths = [0];
    for (let i = 1; i < xs.length; i++) lengths.push(lengths[i - 1] + Math.abs(xs[i] - xs[i - 1]) + Math.abs(ys[i] - ys[i - 1]));
    const total = lengths[lengths.length - 1];
    if (total > CELL * 3) routes.push({ xs, ys, lengths, total });
  }
  const traces = routes.map((r) => r.xs.map((x, i) => `${i ? 'L' : 'M'}${x} ${r.ys[i]}`).join('')).join('');
  const packets: Packet[] = routes.map((route, i) => {
    const threat = i === 2 || i === 6;
    return { route, threat, speed: 55 + random() * 60, offset: random() * 400, tail: threat ? 34 : 52,
             color: threat ? RED : i % 3 === 0 ? TEAL : CYAN };
  });
  return { grid, traces, routes, packets };
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

/** Where a packet is: distance along its route, or past the end while its burst plays. */
function travel(p: Packet, time: number) {
  'worklet';
  const cycle = p.route.total + p.speed * 1.6;
  return (time * p.speed + p.offset) % cycle;
}

/**
 * One data packet. Everything here animates transform and opacity only, so the
 * GPU moves it without redrawing anything; the grid underneath is drawn once.
 */
function DataPacket({ p, clock }: { p: Packet; clock: SharedValue<number> }) {
  const head = useAnimatedStyle(() => {
    const d = travel(p, clock.value);
    if (d > p.route.total) return { opacity: 0 };
    const [x, y] = point(p.route, d);
    return { opacity: 1, transform: [{ translateX: x - HEAD / 2 }, { translateY: y - HEAD / 2 }] };
  });
  // The trail lies along the current run; one view for horizontal runs, one for vertical.
  const trail = (horizontal: boolean) => {
    'worklet';
    const d = travel(p, clock.value);
    if (d > p.route.total || d < 2) return { opacity: 0 };
    const [x, y] = point(p.route, d);
    const [bx, by] = point(p.route, d - 2);
    const dx = x - bx, dy = y - by;
    if (horizontal !== Math.abs(dx) >= Math.abs(dy)) return { opacity: 0 };
    const length = Math.min(p.tail, d);
    return horizontal
      ? { opacity: 0.55, transform: [{ translateX: dx >= 0 ? x - length : x }, { translateY: y - 0.8 }, { scaleX: length / p.tail }] }
      : { opacity: 0.55, transform: [{ translateX: x - 0.8 }, { translateY: dy >= 0 ? y - length : y }, { scaleY: length / p.tail }] };
  };
  const trailH = useAnimatedStyle(() => trail(true));
  const trailV = useAnimatedStyle(() => trail(false));
  const end = p.route.xs.length - 1;
  const ring = p.threat ? 40 : 26;
  const burst = useAnimatedStyle(() => {
    // At the end node: a ring expands; a threat gets a bigger red one, as if stopped.
    const d = travel(p, clock.value);
    const phase = d > p.route.total ? Math.min(1, (d - p.route.total) / (p.speed * 1.1)) : 1;
    return { opacity: (p.threat ? 0.8 : 0.45) * (1 - phase), transform: [{ scale: 0.15 + 0.85 * phase }] };
  });
  return (
    <>
      <Animated.View style={[st.dot, { width: p.tail, height: 1.6, backgroundColor: p.color, transformOrigin: 'left' }, trailH]} />
      <Animated.View style={[st.dot, { width: 1.6, height: p.tail, backgroundColor: p.color, transformOrigin: 'top' }, trailV]} />
      <Animated.View style={[st.dot, { width: HEAD, height: HEAD, borderRadius: HEAD / 2, backgroundColor: p.color, shadowColor: p.color }, st.glow, head]} />
      <Animated.View style={[st.dot, { left: p.route.xs[end] - ring / 2, top: p.route.ys[end] - ring / 2, width: ring, height: ring,
        borderRadius: ring / 2, borderWidth: p.threat ? 1.5 : 1, borderColor: p.color }, burst]} />
    </>
  );
}

/** Grid, traces and nodes: drawn once and kept as a texture, never redrawn by the animation. */
const StaticNetwork = memo(function StaticNetwork({ width, height, net }: { width: number; height: number; net: ReturnType<typeof buildNetwork> }) {
  return (
    <View style={StyleSheet.absoluteFill} renderToHardwareTextureAndroid shouldRasterizeIOS>
      <Svg width={width} height={height}>
        <Path d={net.grid} stroke={CYAN} strokeOpacity={0.05} strokeWidth={1} />
        <Path d={net.traces} stroke={CYAN} strokeOpacity={0.13} strokeWidth={1.1} fill="none" />
        {net.routes.map((r, i) => (
          <Rect key={i} x={r.xs[r.xs.length - 1] - 1.6} y={r.ys[r.ys.length - 1] - 1.6} width={3.2} height={3.2} fill={CYAN} fillOpacity={0.45} />
        ))}
      </Svg>
    </View>
  );
});

export function NetworkBackground() {
  const { width, height } = useWindowDimensions();
  const focused = useIsFocused();
  const reduced = useReducedMotion();
  const net = useMemo(() => buildNetwork(width, height), [width, height]);
  const clock = useSharedValue(4);
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
    const t = clock.value % CYCLE;
    const visible = t < SWEEP;
    return { opacity: visible ? 1 : 0, transform: [{ translateY: visible ? -BEAM + (height + BEAM * 2) * (t / SWEEP) : -BEAM * 2 }] };
  });

  return (
    <View pointerEvents="none" style={StyleSheet.absoluteFill}>
      <LinearGradient colors={['#04080f', '#071321', '#050a12']} style={StyleSheet.absoluteFill} />
      <View style={{ position: 'absolute', top: -170, left: -110 }}><Glow size={440} color="#1f7fb3" opacity={0.26} /></View>
      <StaticNetwork width={width} height={height} net={net} />
      {moving ? net.packets.map((p, i) => <DataPacket key={i} p={p} clock={clock} />) : null}
      {moving ? (
        <Animated.View style={[{ position: 'absolute', left: 0, right: 0, height: BEAM }, beam]}>
          <LinearGradient colors={['rgba(119,220,255,0)', 'rgba(119,220,255,0.06)', 'rgba(119,220,255,0.15)']} locations={[0, 0.8, 1]} style={StyleSheet.absoluteFill} />
          <View style={{ position: 'absolute', left: 0, right: 0, bottom: 0, height: 1, backgroundColor: 'rgba(119,220,255,0.45)' }} />
        </Animated.View>
      ) : null}
    </View>
  );
}

const HEAD = 4.4;
const st = StyleSheet.create({
  dot: { position: 'absolute', left: 0, top: 0 },
  glow: { shadowOpacity: 0.9, shadowRadius: 5, shadowOffset: { width: 0, height: 0 } },
});
