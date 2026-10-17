import * as Haptics from 'expo-haptics';
import { LinearGradient } from 'expo-linear-gradient';
import { useEffect, type ReactNode } from 'react';
import { ActivityIndicator, Pressable, StyleSheet, Text, TextInput, View, type TextInputProps, type ViewStyle } from 'react-native';
import Animated, { Easing, useAnimatedStyle, useSharedValue, withRepeat, withTiming } from 'react-native-reanimated';

import { Icon, type IconName } from '@/components/icon';
import { colors, fonts, gradients, radius, verdictStyle } from '@/lib/theme';

export function Chips({ items }: { items: string[] }) {
  return (
    <View style={{ flexDirection: 'row', flexWrap: 'wrap', gap: 8 }}>
      {items.map((c) => <Chip key={c}>{c}</Chip>)}
    </View>
  );
}

export function Card({ children, style, glow }: { children: ReactNode; style?: ViewStyle; glow?: boolean }) {
  const body = (
    <LinearGradient colors={gradients.card} start={{ x: 0, y: 0 }} end={{ x: 1, y: 1 }} style={[styles.card, glow && { borderWidth: 0 }, style]}>
      {children}
    </LinearGradient>
  );
  if (!glow) return body;
  return <LinearGradient colors={gradients.ai} start={{ x: 0, y: 0 }} end={{ x: 1, y: 1 }} style={{ borderRadius: radius.lg, padding: 1.2 }}>{body}</LinearGradient>;
}

type ButtonKind = 'primary' | 'secondary' | 'danger' | 'link';

export function Button({ label, onPress, busy, kind = 'primary', disabled, icon, flex, arrow }: {
  label: string; onPress: () => void; busy?: boolean; kind?: ButtonKind; disabled?: boolean; icon?: IconName; flex?: number; arrow?: string;
}) {
  const off = disabled || busy;
  const fg = kind === 'primary' ? colors.onAccent : kind === 'danger' ? colors.red : kind === 'link' ? colors.cyan : colors.text;
  const inner = busy ? <ActivityIndicator color={fg} /> : (
    <View style={styles.buttonRow}>
      {icon ? <Icon name={icon} size={18} color={fg} /> : null}
      <Text style={[styles.buttonText, { color: fg }, kind === 'link' && styles.linkText]}>{label}</Text>
      {arrow ? <Text style={[styles.buttonText, { color: fg }]}>{arrow}</Text> : null}
    </View>
  );
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={label}
      accessibilityState={{ disabled: !!off, busy: !!busy }}
      onPress={off ? undefined : () => { Haptics.selectionAsync().catch(() => {}); onPress(); }}
      style={({ pressed }) => [{ flex, opacity: off ? (kind === 'primary' && !busy ? 0.8 : 0.5) : 1, transform: [{ scale: pressed ? 0.98 : 1 }] }]}>
      {kind === 'primary' ? (
        <LinearGradient colors={gradients.accent} start={{ x: 0, y: 0 }} end={{ x: 1, y: 0 }} style={styles.button}>{inner}</LinearGradient>
      ) : kind === 'link' ? (
        <View style={{ paddingVertical: 6 }}>{inner}</View>
      ) : (
        <View style={[styles.button, kind === 'danger' ? styles.danger : styles.secondary]}>{inner}</View>
      )}
    </Pressable>
  );
}

export function Field(props: TextInputProps & { label?: string; right?: ReactNode; icon?: IconName }) {
  const { label, style, right, icon, ...rest } = props;
  return (
    <View style={{ gap: 8 }}>
      {label ? <Text style={styles.label}>{label}</Text> : null}
      <View style={styles.inputWrap}>
        {icon ? <Icon name={icon} size={18} color={colors.faint} /> : null}
        <TextInput placeholderTextColor="#5f7590" style={[styles.input, style]} {...rest} />
        {right}
      </View>
    </View>
  );
}

export function ErrorText({ children }: { children?: string | null }) {
  if (!children) return null;
  return (
    <View style={styles.errorBox} accessibilityLiveRegion="polite">
      <Icon name="alert" size={17} color={colors.amber} />
      <Text style={styles.error}>{children}</Text>
    </View>
  );
}

export function Muted({ children, center }: { children: ReactNode; center?: boolean }) {
  return <Text style={[styles.muted, center && { textAlign: 'center' }]}>{children}</Text>;
}

export function Body({ children, selectable }: { children: ReactNode; selectable?: boolean }) {
  return <Text style={styles.body} selectable={selectable}>{children}</Text>;
}

export function Chip({ children, color = colors.soft }: { children: ReactNode; color?: string }) {
  return <View style={styles.chip}><Text style={{ color, fontSize: 12.5, fontFamily: fonts.medium }}>{children}</Text></View>;
}

/** Verdict pill in the website's outlined style. */
export function VerdictBadge({ verdict, score, big }: { verdict?: string | null; score?: number | null; big?: boolean }) {
  const v = verdictStyle(verdict);
  return (
    <View style={[styles.badge, { borderColor: v.color + '88', backgroundColor: v.color + '14' }, big && { paddingVertical: 7, paddingHorizontal: 13 }]}>
      <Text style={[styles.badgeText, { color: v.color }, big && { fontSize: 14 }]}>{v.label}{typeof score === 'number' ? `  ·  ${score}/100` : ''}</Text>
    </View>
  );
}

/** A pulsing placeholder while content loads. */
export function Skeleton({ height = 64, style }: { height?: number; style?: ViewStyle }) {
  const opacity = useSharedValue(0.4);
  useEffect(() => {
    opacity.value = withRepeat(withTiming(0.9, { duration: 800, easing: Easing.inOut(Easing.quad) }), -1, true);
  }, [opacity]);
  const animated = useAnimatedStyle(() => ({ opacity: opacity.value }));
  return <Animated.View style={[{ height, borderRadius: radius.md, backgroundColor: colors.surface2 }, animated, style]} />;
}

export const styles = StyleSheet.create({
  kicker: { fontFamily: fonts.mono, fontSize: 12, letterSpacing: 2, color: colors.cyan },
  muted: { color: colors.muted, fontSize: 14, lineHeight: 22, fontFamily: fonts.regular },
  body: { color: colors.text, fontSize: 15, lineHeight: 24, fontFamily: fonts.regular },
  label: { color: colors.text, fontSize: 14.5, fontFamily: fonts.semibold },
  card: { borderRadius: radius.lg, borderWidth: 1, borderColor: colors.line, padding: 20, gap: 14, overflow: 'hidden' },
  button: { minHeight: 50, borderRadius: 10, alignItems: 'center', justifyContent: 'center', paddingHorizontal: 18 },
  buttonRow: { flexDirection: 'row', alignItems: 'center', gap: 10 },
  secondary: { backgroundColor: '#132437', borderWidth: 1, borderColor: '#2c485f' },
  danger: { backgroundColor: 'rgba(251,113,133,.08)', borderWidth: 1, borderColor: 'rgba(251,113,133,.4)' },
  buttonText: { fontSize: 15, fontFamily: fonts.bold },
  linkText: { textDecorationLine: 'underline', fontFamily: fonts.semibold },
  inputWrap: { flexDirection: 'row', alignItems: 'center', gap: 12, minHeight: 54, borderRadius: 10, borderWidth: 1, borderColor: 'rgba(135,169,191,.27)', backgroundColor: colors.input, paddingLeft: 15, paddingRight: 6 },
  input: { flex: 1, color: colors.text, fontSize: 15, paddingVertical: 12, fontFamily: fonts.regular },
  errorBox: { flexDirection: 'row', gap: 8, alignItems: 'flex-start', padding: 12, borderRadius: 10, backgroundColor: 'rgba(251,191,36,.08)', borderWidth: 1, borderColor: 'rgba(251,191,36,.3)' },
  error: { color: '#fde68a', fontSize: 14, lineHeight: 20, flex: 1, fontFamily: fonts.regular },
  chip: { paddingVertical: 6, paddingHorizontal: 12, borderRadius: 999, backgroundColor: 'rgba(13,24,40,.7)', borderWidth: 1, borderColor: 'rgba(145,188,220,.18)' },
  badge: { alignSelf: 'flex-start', borderWidth: 1, borderRadius: 7, paddingVertical: 4, paddingHorizontal: 9 },
  badgeText: { fontSize: 12, fontFamily: fonts.semibold },
});
