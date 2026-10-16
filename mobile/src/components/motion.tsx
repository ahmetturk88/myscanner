import { useEffect } from 'react';
import { StyleSheet, View } from 'react-native';
import Animated, {
  Easing, useAnimatedProps, useAnimatedStyle, useSharedValue, withDelay, withRepeat, withSequence, withTiming,
} from 'react-native-reanimated';
import Svg, { Circle, Defs, LinearGradient, Stop } from 'react-native-svg';

import { BrandMark } from '@/components/brand';
import { colors } from '@/lib/theme';

const AnimatedCircle = Animated.createAnimatedComponent(Circle);

/** The brand mark inside a radar that sweeps while a scan runs. */
export function ScanOrb({ size = 170, active = true }: { size?: number; active?: boolean }) {
  const turn = useSharedValue(0);
  const pulse = useSharedValue(0);
  useEffect(() => {
    if (!active) return;
    turn.value = withRepeat(withTiming(1, { duration: 2400, easing: Easing.linear }), -1);
    pulse.value = withRepeat(withTiming(1, { duration: 2200, easing: Easing.out(Easing.quad) }), -1);
  }, [active, turn, pulse]);
  const sweep = useAnimatedStyle(() => ({ transform: [{ rotate: `${turn.value * 360}deg` }] }));
  const ring = (delay: number) => {
    'worklet';
    return { opacity: 0.7 * (1 - ((pulse.value + delay) % 1)), transform: [{ scale: 1 + 0.55 * ((pulse.value + delay) % 1) }] };
  };
  const ringA = useAnimatedStyle(() => ring(0));
  const ringB = useAnimatedStyle(() => ring(0.5));
  return (
    <View style={{ width: size * 1.6, height: size * 1.6, alignItems: 'center', justifyContent: 'center' }}>
      {active ? <>
        <Animated.View style={[styles.ring, { width: size, height: size, borderRadius: size }, ringA]} />
        <Animated.View style={[styles.ring, { width: size, height: size, borderRadius: size }, ringB]} />
      </> : null}
      <View style={[styles.orb, { width: size, height: size, borderRadius: size }]}>
        {active ? (
          <Animated.View style={[StyleSheet.absoluteFill, sweep]}>
            <View style={{ position: 'absolute', left: size / 2, top: 0, width: size / 2, height: size / 2, borderTopRightRadius: size,
              backgroundColor: 'rgba(34,211,238,.22)' }} />
          </Animated.View>
        ) : null}
        <BrandMark size={size * 0.5} />
      </View>
    </View>
  );
}

/** A circular score gauge that fills when it appears. */
export function Gauge({ score, color, size = 170 }: { score: number | null; color: string; size?: number }) {
  const r = 50;
  const length = 2 * Math.PI * r;
  const progress = useSharedValue(0);
  useEffect(() => {
    progress.value = withDelay(150, withTiming(Math.max(0, Math.min(100, score ?? 0)) / 100, { duration: 1100, easing: Easing.out(Easing.cubic) }));
  }, [score, progress]);
  const props = useAnimatedProps(() => ({ strokeDashoffset: length * (1 - progress.value) }));
  return (
    <Svg width={size} height={size} viewBox="0 0 120 120">
      <Defs>
        <LinearGradient id="gauge" x1="0" y1="0" x2="1" y2="1"><Stop offset="0" stopColor={color} /><Stop offset="1" stopColor={color} stopOpacity={0.6} /></LinearGradient>
      </Defs>
      <Circle cx="60" cy="60" r={r} fill="none" stroke="#1b2a40" strokeWidth={10} />
      <AnimatedCircle cx="60" cy="60" r={r} fill="none" stroke="url(#gauge)" strokeWidth={10} strokeLinecap="round"
        strokeDasharray={`${length}`} animatedProps={props} transform="rotate(-90 60 60)" />
    </Svg>
  );
}

/** Three dots that bounce while an answer is being written. */
export function TypingDots() {
  const t = useSharedValue(0);
  useEffect(() => { t.value = withRepeat(withTiming(1, { duration: 900 }), -1); }, [t]);
  const dot = (offset: number) => {
    'worklet';
    return { opacity: 0.35 + 0.65 * Math.max(0, Math.sin(Math.PI * ((t.value + offset) % 1))),
    transform: [{ translateY: -3 * Math.max(0, Math.sin(Math.PI * ((t.value + offset) % 1))) }] };
  };
  const a = useAnimatedStyle(() => dot(0));
  const b = useAnimatedStyle(() => dot(0.66));
  const c = useAnimatedStyle(() => dot(0.33));
  return (
    <View accessibilityLabel="Writing" style={{ flexDirection: 'row', gap: 6, paddingVertical: 6 }}>
      {[a, b, c].map((s, i) => <Animated.View key={i} style={[{ width: 8, height: 8, borderRadius: 4, backgroundColor: colors.cyanSoft }, s]} />)}
    </View>
  );
}

/** A thin light beam that sweeps down and up across its parent. */
export function Beam({ height }: { height: number }) {
  const y = useSharedValue(0);
  useEffect(() => {
    y.value = withRepeat(withSequence(withTiming(1, { duration: 2600, easing: Easing.inOut(Easing.quad) }), withTiming(0, { duration: 2600, easing: Easing.inOut(Easing.quad) })), -1);
  }, [y]);
  const style = useAnimatedStyle(() => ({ transform: [{ translateY: y.value * height }] }));
  return (
    <Animated.View pointerEvents="none" style={[{ position: 'absolute', left: 0, right: 0, top: 0, height: 2 }, style]}>
      <View style={{ flex: 1, backgroundColor: colors.cyanSoft, opacity: 0.55 }} />
    </Animated.View>
  );
}

/** Fades and lifts its children in once, optionally after a delay. */
export function Appear({ children, delay = 0 }: { children: React.ReactNode; delay?: number }) {
  const v = useSharedValue(0);
  useEffect(() => { v.value = withDelay(delay, withTiming(1, { duration: 420, easing: Easing.out(Easing.cubic) })); }, [v, delay]);
  const style = useAnimatedStyle(() => ({ opacity: v.value, transform: [{ translateY: (1 - v.value) * 14 }] }));
  return <Animated.View style={style}>{children}</Animated.View>;
}

const styles = StyleSheet.create({
  ring: { position: 'absolute', borderWidth: 1, borderColor: 'rgba(34,211,238,.45)' },
  orb: { alignItems: 'center', justifyContent: 'center', overflow: 'hidden', backgroundColor: '#0b2238', borderWidth: 1, borderColor: 'rgba(34,211,238,.4)' },
});
