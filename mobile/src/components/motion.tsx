import * as Haptics from '@/lib/haptics';
import { LinearGradient as ExpoGradient } from 'expo-linear-gradient';
import { useEffect, useState } from 'react';
import { Pressable, StyleSheet, View } from 'react-native';
import Animated, {
  Easing, FadeInDown, useAnimatedProps, useAnimatedStyle, useSharedValue, withDelay, withRepeat, withSequence, withSpring, withTiming,
} from 'react-native-reanimated';
import Svg, { Circle, Defs, LinearGradient, RadialGradient, Stop } from 'react-native-svg';

import { BrandMark } from '@/components/brand';
import { t } from '@/lib/i18n';
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
  const phase = useSharedValue(0);
  useEffect(() => { phase.value = withRepeat(withTiming(1, { duration: 900 }), -1); }, [phase]);
  const dot = (offset: number) => {
    'worklet';
    return { opacity: 0.35 + 0.65 * Math.max(0, Math.sin(Math.PI * ((phase.value + offset) % 1))),
    transform: [{ translateY: -3 * Math.max(0, Math.sin(Math.PI * ((phase.value + offset) % 1))) }] };
  };
  const a = useAnimatedStyle(() => dot(0));
  const b = useAnimatedStyle(() => dot(0.66));
  const c = useAnimatedStyle(() => dot(0.33));
  return (
    <View accessibilityLabel={t('Writing')} style={{ flexDirection: 'row', gap: 6, paddingVertical: 6 }}>
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

const styles = StyleSheet.create({
  ring: { position: 'absolute', borderWidth: 1, borderColor: 'rgba(34,211,238,.45)' },
  orb: { alignItems: 'center', justifyContent: 'center', overflow: 'hidden', backgroundColor: '#0b2238', borderWidth: 1, borderColor: 'rgba(34,211,238,.4)' },
});

/** Scales down slightly while pressed, with a light haptic tick. */
export function PressableScale({ children, onPress, style, disabled, scale = 0.97, haptic = true, accessibilityLabel, accessibilityRole = 'button' }: {
  children: React.ReactNode; onPress?: () => void; style?: any; disabled?: boolean; scale?: number; haptic?: boolean;
  accessibilityLabel?: string; accessibilityRole?: 'button' | 'link' | 'tab';
}) {
  const pressed = useSharedValue(0);
  const animated = useAnimatedStyle(() => ({ transform: [{ scale: 1 - (1 - scale) * pressed.value }] }));
  return (
    <AnimatedPressable accessibilityRole={accessibilityRole} accessibilityLabel={accessibilityLabel} disabled={disabled}
      onPressIn={() => { pressed.value = withSpring(1, SPRING); }} onPressOut={() => { pressed.value = withSpring(0, SPRING); }}
      onPress={onPress ? () => { if (haptic) Haptics.selectionAsync().catch(() => {}); onPress(); } : undefined}
      style={[style, animated]}>
      {children}
    </AnimatedPressable>
  );
}

const SPRING = { damping: 18, stiffness: 320, mass: 0.6 };
const AnimatedPressable = Animated.createAnimatedComponent(Pressable);

/** Two soft colour glows that drift slowly behind a screen. */
export function Ambient() {
  const t = useSharedValue(0);
  useEffect(() => {
    t.value = withRepeat(withTiming(1, { duration: 9000, easing: Easing.inOut(Easing.sin) }), -1, true);
  }, [t]);
  const a = useAnimatedStyle(() => ({ transform: [{ translateX: -40 + 80 * t.value }, { translateY: 30 * t.value }, { scale: 1 + 0.15 * t.value }] }));
  const b = useAnimatedStyle(() => ({ transform: [{ translateX: 50 - 90 * t.value }, { translateY: -40 * t.value }] }));
  return (
    <View pointerEvents="none" style={StyleSheet.absoluteFill}>
      <Animated.View style={[{ position: 'absolute', top: -140, left: -60 }, a]}><Glow size={420} color="#1f7fb3" opacity={0.32} /></Animated.View>
      <Animated.View style={[{ position: 'absolute', top: 260, right: -180 }, b]}><Glow size={420} color="#5b3fb0" opacity={0.22} /></Animated.View>
    </View>
  );
}

/** A round radial glow. */
export function Glow({ size, color, opacity = 0.4 }: { size: number; color: string; opacity?: number }) {
  const id = `glow${color.replace(/[^a-z0-9]/gi, '')}`;
  return (
    <Svg width={size} height={size}>
      <Defs>
        <RadialGradient id={id} cx="50%" cy="50%" r="50%">
          <Stop offset="0" stopColor={color} stopOpacity={opacity} />
          <Stop offset="1" stopColor={color} stopOpacity={0} />
        </RadialGradient>
      </Defs>
      <Circle cx={size / 2} cy={size / 2} r={size / 2} fill={`url(#${id})`} />
    </Svg>
  );
}

/** Rings that ripple out from behind their children, for live or featured icons. */
export function Pulse({ children, size, color = colors.cyan, active = true }: { children: React.ReactNode; size: number; color?: string; active?: boolean }) {
  const p = useSharedValue(0);
  useEffect(() => {
    if (active) p.value = withRepeat(withTiming(1, { duration: 2000, easing: Easing.out(Easing.quad) }), -1);
    else p.value = 0;
  }, [active, p]);
  const ring = (offset: number) => {
    'worklet';
    const v = (p.value + offset) % 1;
    return { opacity: active ? 0.6 * (1 - v) : 0, transform: [{ scale: 1 + 0.7 * v }] };
  };
  const a = useAnimatedStyle(() => ring(0));
  const b = useAnimatedStyle(() => ring(0.5));
  const base = { position: 'absolute' as const, width: size, height: size, borderRadius: size / 2.6, borderWidth: 1.5, borderColor: color };
  return (
    <View style={{ width: size, height: size, alignItems: 'center', justifyContent: 'center' }}>
      <Animated.View style={[base, a]} />
      <Animated.View style={[base, b]} />
      {children}
    </View>
  );
}

/** Slowly turns its children, e.g. a gradient ring. */
export function Spin({ children, duration = 6000 }: { children: React.ReactNode; duration?: number }) {
  const r = useSharedValue(0);
  useEffect(() => { r.value = withRepeat(withTiming(1, { duration, easing: Easing.linear }), -1); }, [r, duration]);
  const style = useAnimatedStyle(() => ({ transform: [{ rotate: `${r.value * 360}deg` }] }));
  return <Animated.View style={style}>{children}</Animated.View>;
}

/** Counts up to a number when it first appears or changes. */
export function useCountUp(target: number | null | undefined, duration = 900) {
  const [value, setValue] = useState(0);
  useEffect(() => {
    if (typeof target !== 'number') return;
    let frame = 0;
    const start = Date.now();
    const tick = () => {
      const k = Math.min(1, (Date.now() - start) / duration);
      setValue(Math.round(target * (1 - Math.pow(1 - k, 3))));
      if (k < 1) frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [target, duration]);
  return typeof target === 'number' ? value : null;
}

/** A bar that grows to its value. */
export function Bar({ percent, colors: tint, delay = 0 }: { percent: number; colors: readonly [string, string, ...string[]]; delay?: number }) {
  const w = useSharedValue(0);
  useEffect(() => { w.value = withDelay(delay, withTiming(Math.max(3, Math.min(100, percent)), { duration: 900, easing: Easing.out(Easing.cubic) })); }, [percent, delay, w]);
  const style = useAnimatedStyle(() => ({ width: `${w.value}%` }));
  return (
    <View style={{ height: 6, borderRadius: 6, backgroundColor: '#152338', overflow: 'hidden' }}>
      <Animated.View style={[{ height: '100%', borderRadius: 6, overflow: 'hidden' }, style]}>
        <ExpoGradient colors={tint} start={{ x: 0, y: 0 }} end={{ x: 1, y: 0 }} style={StyleSheet.absoluteFill} />
      </Animated.View>
    </View>
  );
}

/** Entrance used for lists and sections: fade and rise, staggered by index. */
export const enter = (i = 0) => FadeInDown.delay(Math.min(i, 8) * 70).duration(480).easing(Easing.out(Easing.cubic));
