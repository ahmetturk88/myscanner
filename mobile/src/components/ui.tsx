import * as Haptics from 'expo-haptics';
import { LinearGradient } from 'expo-linear-gradient';
import { router } from 'expo-router';
import { useEffect, type ReactNode } from 'react';
import { ActivityIndicator, Pressable, ScrollView, StyleSheet, Text, TextInput, View, type TextInputProps, type ViewStyle } from 'react-native';
import Animated, { Easing, useAnimatedStyle, useSharedValue, withRepeat, withTiming } from 'react-native-reanimated';
import { SafeAreaView } from 'react-native-safe-area-context';

import { Icon, type IconName } from '@/components/icon';
import { colors, gradients, radius, space, verdictStyle } from '@/lib/theme';

/** Dark screen with the brand's soft top glow. */
export function Backdrop({ children }: { children: ReactNode }) {
  return (
    <View style={{ flex: 1, backgroundColor: colors.bg }}>
      <LinearGradient colors={gradients.screen} locations={[0, 0.45, 1]} style={StyleSheet.absoluteFill} />
      {children}
    </View>
  );
}

export function Screen({ children, scroll = true, bottom = 40, edges = ['top'] }: {
  children: ReactNode; scroll?: boolean; bottom?: number; edges?: ('top' | 'bottom')[];
}) {
  return (
    <Backdrop>
      <SafeAreaView style={{ flex: 1 }} edges={edges}>
        {scroll ? (
          <ScrollView contentContainerStyle={[styles.content, { paddingBottom: bottom }]} keyboardShouldPersistTaps="handled" showsVerticalScrollIndicator={false}>
            {children}
          </ScrollView>
        ) : (
          <View style={[styles.content, { flex: 1, paddingBottom: 0 }]}>{children}</View>
        )}
      </SafeAreaView>
    </Backdrop>
  );
}

/** In-screen header with an optional back button and right-hand action. */
export function Header({ title, back = true, right }: { title: string; back?: boolean; right?: ReactNode }) {
  return (
    <View style={styles.header}>
      {back ? (
        <Pressable accessibilityRole="button" accessibilityLabel="Back" hitSlop={12} onPress={() => router.back()} style={styles.iconButton}>
          <Icon name="back" color={colors.text} />
        </Pressable>
      ) : null}
      <Text style={styles.headerTitle} numberOfLines={1}>{title}</Text>
      <View style={{ marginLeft: 'auto' }}>{right}</View>
    </View>
  );
}

export function Title({ kicker, children, sub }: { kicker?: string; children: ReactNode; sub?: string }) {
  return (
    <View style={{ gap: 6, marginBottom: 4 }}>
      {kicker ? <Text style={styles.kicker}>{kicker}</Text> : null}
      <Text style={styles.title}>{children}</Text>
      {sub ? <Text style={styles.muted}>{sub}</Text> : null}
    </View>
  );
}

export function Section({ children, right }: { children: string; right?: ReactNode }) {
  return (
    <View style={{ flexDirection: 'row', alignItems: 'center', marginTop: 6 }}>
      <Text style={styles.section}>{children}</Text>
      <View style={{ marginLeft: 'auto' }}>{right}</View>
    </View>
  );
}

export function Card({ children, style, glow }: { children: ReactNode; style?: ViewStyle; glow?: boolean }) {
  if (glow) {
    return (
      <LinearGradient colors={gradients.ai} start={{ x: 0, y: 0 }} end={{ x: 1, y: 1 }} style={{ borderRadius: radius.lg, padding: 1.5 }}>
        <View style={[styles.card, { borderWidth: 0, backgroundColor: '#0d1a2c' }, style]}>{children}</View>
      </LinearGradient>
    );
  }
  return <View style={[styles.card, style]}>{children}</View>;
}

type ButtonKind = 'primary' | 'secondary' | 'danger';

export function Button({ label, onPress, busy, kind = 'primary', disabled, icon, flex }: {
  label: string; onPress: () => void; busy?: boolean; kind?: ButtonKind; disabled?: boolean; icon?: IconName; flex?: number;
}) {
  const off = disabled || busy;
  const fg = kind === 'primary' ? colors.onAccent : kind === 'danger' ? colors.red : colors.soft;
  const inner = busy ? <ActivityIndicator color={fg} /> : (
    <View style={styles.buttonRow}>
      {icon ? <Icon name={icon} size={19} color={fg} /> : null}
      <Text style={[styles.buttonText, { color: fg }]}>{label}</Text>
    </View>
  );
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={label}
      accessibilityState={{ disabled: !!off, busy: !!busy }}
      onPress={off ? undefined : () => { Haptics.selectionAsync().catch(() => {}); onPress(); }}
      style={({ pressed }) => [{ flex, opacity: off ? 0.55 : 1, transform: [{ scale: pressed ? 0.98 : 1 }] }]}>
      {kind === 'primary' ? (
        <LinearGradient colors={gradients.accent} start={{ x: 0, y: 0 }} end={{ x: 1, y: 0 }} style={[styles.button, styles.primaryShadow]}>{inner}</LinearGradient>
      ) : (
        <View style={[styles.button, kind === 'danger' ? styles.danger : styles.secondary]}>{inner}</View>
      )}
    </Pressable>
  );
}

export function Field(props: TextInputProps & { label?: string; right?: ReactNode; icon?: IconName }) {
  const { label, style, right, icon, ...rest } = props;
  return (
    <View style={{ gap: 6 }}>
      {label ? <Text style={styles.label}>{label}</Text> : null}
      <View style={styles.inputWrap}>
        {icon ? <Icon name={icon} size={19} color={colors.faint} /> : null}
        <TextInput placeholderTextColor={colors.faint} style={[styles.input, style]} {...rest} />
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

export function Chip({ children, color = colors.muted }: { children: ReactNode; color?: string }) {
  return <View style={styles.chip}><Text style={{ color, fontSize: 12, fontWeight: '600' }}>{children}</Text></View>;
}

export function VerdictBadge({ verdict, score, big }: { verdict?: string | null; score?: number | null; big?: boolean }) {
  const v = verdictStyle(verdict);
  return (
    <View style={[styles.badge, { borderColor: v.color + '88', backgroundColor: v.color + '18' }, big && { paddingVertical: 9, paddingHorizontal: 15 }]}>
      <View style={[styles.dot, { backgroundColor: v.color }]} />
      <Text style={[styles.badgeText, { color: v.color }, big && { fontSize: 16 }]}>{v.label}{typeof score === 'number' ? `  ·  ${score}/100` : ''}</Text>
    </View>
  );
}

/** A pulsing placeholder while content loads. */
export function Skeleton({ height = 72, style }: { height?: number; style?: ViewStyle }) {
  const opacity = useSharedValue(0.4);
  useEffect(() => {
    opacity.value = withRepeat(withTiming(0.9, { duration: 800, easing: Easing.inOut(Easing.quad) }), -1, true);
  }, [opacity]);
  const animated = useAnimatedStyle(() => ({ opacity: opacity.value }));
  return <Animated.View style={[{ height, borderRadius: radius.md, backgroundColor: colors.surface2 }, animated, style]} />;
}

export const styles = StyleSheet.create({
  content: { padding: space.md, gap: 14 },
  header: { flexDirection: 'row', alignItems: 'center', gap: 10, minHeight: 44 },
  headerTitle: { color: colors.text, fontSize: 19, fontWeight: '800', flexShrink: 1 },
  iconButton: { width: 40, height: 40, borderRadius: 13, alignItems: 'center', justifyContent: 'center', backgroundColor: colors.surface2, borderWidth: 1, borderColor: colors.line },
  kicker: { color: colors.cyanSoft, fontSize: 12, letterSpacing: 2.2, fontWeight: '800' },
  title: { color: colors.text, fontSize: 28, fontWeight: '800', letterSpacing: -0.6 },
  section: { color: colors.text, fontSize: 17, fontWeight: '800' },
  muted: { color: colors.muted, fontSize: 14.5, lineHeight: 21 },
  body: { color: colors.text, fontSize: 15, lineHeight: 23 },
  label: { color: colors.muted, fontSize: 13, fontWeight: '600' },
  card: { backgroundColor: colors.surface, borderRadius: radius.lg, borderWidth: 1, borderColor: colors.line, padding: space.md, gap: 12 },
  button: { minHeight: 52, borderRadius: radius.md, alignItems: 'center', justifyContent: 'center', paddingHorizontal: space.md },
  buttonRow: { flexDirection: 'row', alignItems: 'center', gap: 8 },
  primaryShadow: { shadowColor: colors.cyan, shadowOpacity: 0.45, shadowRadius: 14, shadowOffset: { width: 0, height: 8 }, elevation: 6 },
  secondary: { backgroundColor: colors.surface2, borderWidth: 1, borderColor: colors.line2 },
  danger: { backgroundColor: 'rgba(251,113,133,.08)', borderWidth: 1, borderColor: 'rgba(251,113,133,.4)' },
  buttonText: { fontSize: 16, fontWeight: '800' },
  inputWrap: { flexDirection: 'row', alignItems: 'center', gap: 10, minHeight: 54, borderRadius: radius.md, borderWidth: 1, borderColor: colors.line2, backgroundColor: colors.input, paddingLeft: 14, paddingRight: 6 },
  input: { flex: 1, color: colors.text, fontSize: 16, paddingVertical: 12 },
  errorBox: { flexDirection: 'row', gap: 8, alignItems: 'flex-start', padding: 12, borderRadius: radius.sm, backgroundColor: 'rgba(251,191,36,.08)', borderWidth: 1, borderColor: 'rgba(251,191,36,.3)' },
  error: { color: '#fde68a', fontSize: 14, lineHeight: 20, flex: 1 },
  chip: { paddingVertical: 5, paddingHorizontal: 10, borderRadius: 999, backgroundColor: colors.surface2, borderWidth: 1, borderColor: colors.line },
  badge: { flexDirection: 'row', alignItems: 'center', alignSelf: 'flex-start', gap: 8, borderWidth: 1, borderRadius: 999, paddingVertical: 6, paddingHorizontal: 12 },
  dot: { width: 8, height: 8, borderRadius: 4 },
  badgeText: { fontSize: 14, fontWeight: '800' },
});
