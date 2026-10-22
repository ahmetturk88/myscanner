/**
 * The app's background: a secure data network, matching the website
 * (static/net_background.js). Circuit-like traces on a fine grid carry data
 * packets between nodes, a scan beam sweeps down the screen, and now and then
 * a red packet is stopped at a checkpoint node.
 *
 * Everything moves on the UI thread from one clock (useFrameCallback, ~30 fps).
 * The clock stops when the screen is not focused, and the network is drawn
 * still for people who turn on Reduce motion.
 */
import { useIsFocused } from 'expo-router';
import { LinearGradient } from 'expo-linear-gradient';
import { useEffect, useMemo } from 'react';
import { StyleSheet, useWindowDimensions, View } from 'react-native';
import Animated, { useAnimatedProps, useAnimatedStyle, useFrameCallback, useReducedMotion, useSharedValue, type SharedValue } from 'react-native-reanimated';
import Svg, { Circle, Path, Rect } from 'react-native-svg';

import { Glow } from '@/components/motion';

const AnimatedPath = Animated.createAnimatedComponent(Path);
const AnimatedCircle = Animated.createAnimatedComponent(Circle);

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

function DataPacket({ p, clock }: { p: Packet; clock: SharedValue<number> }) {
  const trail = useAnimatedProps(() => {
    const d = travel(p, clock.value);
    if (d > p.route.total) return { d: 'M0 0', strokeOpacity: 0 };
    const [ax, ay] = point(p.route, d);
    const [bx, by] = point(p.route, d - p.tail / 2);
    const [cx, cy] = point(p.route, d - p.tail);
    return { d: `M${ax} ${ay}L${bx} ${by}L${cx} ${cy}`, strokeOpacity: 0.5 };
  });
  const head = useAnimatedProps(() => {
    const d = travel(p, clock.value);
    if (d > p.route.total) return { cx: -20, cy: -20, opacity: 0 };
    const [x, y] = point(p.route, d);
    return { cx: x, cy: y, opacity: 1 };
  });
  const burst = useAnimatedProps(() => {
    // At the end node: a ring expands; a threat gets a bigger red one, as if stopped.
    const d = travel(p, clock.value);
    const phase = d > p.route.total ? Math.min(1, (d - p.route.total) / (p.speed * 1.1)) : 1;
    return { r: 3 + (p.threat ? 18 : 10) * phase, strokeOpacity: (p.threat ? 0.8 : 0.45) * (1 - phase) };
  });
  const end = p.route.xs.length - 1;
  return (
    <>
      <AnimatedPath animatedProps={trail} stroke={p.color} strokeWidth={1.6} fill="none" strokeLinecap="round" />
      <AnimatedCircle animatedProps={head} r={2.2} fill={p.color} stroke={p.color} strokeWidth={5} strokeOpacity={0.22} />
      <AnimatedCircle animatedProps={burst} cx={p.route.xs[end]} cy={p.route.ys[end]} fill="none" stroke={p.color} strokeWidth={p.threat ? 1.5 : 1} />
    </>
  );
}

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
  const moving = focused && !reduced;
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
      <Svg width={width} height={height} style={StyleSheet.absoluteFill}>
        <Path d={net.grid} stroke={CYAN} strokeOpacity={0.05} strokeWidth={1} />
        <Path d={net.traces} stroke={CYAN} strokeOpacity={0.13} strokeWidth={1.1} fill="none" />
        {net.routes.map((r, i) => (
          <Rect key={i} x={r.xs[r.xs.length - 1] - 1.6} y={r.ys[r.ys.length - 1] - 1.6} width={3.2} height={3.2} fill={CYAN} fillOpacity={0.45} />
        ))}
        {moving ? net.packets.map((p, i) => <DataPacket key={i} p={p} clock={clock} />) : null}
      </Svg>
      {moving ? (
        <Animated.View style={[{ position: 'absolute', left: 0, right: 0, height: BEAM }, beam]}>
          <LinearGradient colors={['rgba(119,220,255,0)', 'rgba(119,220,255,0.06)', 'rgba(119,220,255,0.15)']} locations={[0, 0.8, 1]} style={StyleSheet.absoluteFill} />
          <View style={{ position: 'absolute', left: 0, right: 0, bottom: 0, height: 1, backgroundColor: 'rgba(119,220,255,0.45)' }} />
        </Animated.View>
      ) : null}
    </View>
  );
}
