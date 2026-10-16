import type { ReactNode } from 'react';
import { ActivityIndicator, Pressable, ScrollView, StyleSheet, Text, TextInput, View, type TextInputProps, type ViewStyle } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

import { colors, radius, space, verdictStyle } from '@/lib/theme';

export function Screen({ children, scroll = true }: { children: ReactNode; scroll?: boolean }) {
  return (
    <SafeAreaView style={styles.screen} edges={['top']}>
      {scroll ? (
        <ScrollView contentContainerStyle={styles.content} keyboardShouldPersistTaps="handled">{children}</ScrollView>
      ) : (
        <View style={[styles.content, { flex: 1 }]}>{children}</View>
      )}
    </SafeAreaView>
  );
}

export function Title({ kicker, children, sub }: { kicker?: string; children: ReactNode; sub?: string }) {
  return (
    <View style={{ gap: 6, marginBottom: space.md }}>
      {kicker ? <Text style={styles.kicker}>{kicker}</Text> : null}
      <Text style={styles.title}>{children}</Text>
      {sub ? <Text style={styles.muted}>{sub}</Text> : null}
    </View>
  );
}

export function Card({ children, style }: { children: ReactNode; style?: ViewStyle }) {
  return <View style={[styles.card, style]}>{children}</View>;
}

export function Button({ label, onPress, busy, kind = 'primary', disabled }: {
  label: string; onPress: () => void; busy?: boolean; kind?: 'primary' | 'secondary' | 'danger'; disabled?: boolean;
}) {
  const off = disabled || busy;
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityState={{ disabled: !!off, busy: !!busy }}
      onPress={off ? undefined : onPress}
      style={({ pressed }) => [styles.button, styles[kind], (pressed || off) && { opacity: 0.7 }]}>
      {busy ? <ActivityIndicator color={kind === 'primary' ? colors.onAccent : colors.text} />
        : <Text style={[styles.buttonText, kind === 'primary' && { color: colors.onAccent }, kind === 'danger' && { color: colors.red }]}>{label}</Text>}
    </Pressable>
  );
}

export function Field(props: TextInputProps & { label: string }) {
  const { label, style, ...rest } = props;
  return (
    <View style={{ gap: 6 }}>
      <Text style={styles.label}>{label}</Text>
      <TextInput placeholderTextColor={colors.faint} style={[styles.input, style]} {...rest} />
    </View>
  );
}

export function ErrorText({ children }: { children?: string | null }) {
  return children ? <Text style={styles.error} accessibilityLiveRegion="polite">{children}</Text> : null;
}

export function Muted({ children }: { children: ReactNode }) {
  return <Text style={styles.muted}>{children}</Text>;
}

export function Body({ children, selectable }: { children: ReactNode; selectable?: boolean }) {
  return <Text style={styles.body} selectable={selectable}>{children}</Text>;
}

export function VerdictBadge({ verdict, score }: { verdict?: string | null; score?: number | null }) {
  const v = verdictStyle(verdict);
  return (
    <View style={[styles.badge, { borderColor: v.color }]}>
      <View style={[styles.dot, { backgroundColor: v.color }]} />
      <Text style={[styles.badgeText, { color: v.color }]}>{v.label}{typeof score === 'number' ? `  ·  ${score}/100` : ''}</Text>
    </View>
  );
}

export const styles = StyleSheet.create({
  screen: { flex: 1, backgroundColor: colors.bg },
  content: { padding: space.md, paddingBottom: 40, gap: space.md },
  kicker: { color: colors.cyan, fontSize: 12, letterSpacing: 2, fontWeight: '700' },
  title: { color: colors.text, fontSize: 26, fontWeight: '800', letterSpacing: -0.5 },
  muted: { color: colors.muted, fontSize: 14, lineHeight: 21 },
  body: { color: colors.text, fontSize: 15, lineHeight: 23 },
  label: { color: colors.muted, fontSize: 13, fontWeight: '600' },
  card: { backgroundColor: colors.surface, borderRadius: radius.lg, borderWidth: 1, borderColor: colors.line, padding: space.md, gap: space.sm },
  button: { minHeight: 50, borderRadius: radius.md, alignItems: 'center', justifyContent: 'center', paddingHorizontal: space.md, borderWidth: 1 },
  primary: { backgroundColor: colors.cyan, borderColor: colors.cyan },
  secondary: { backgroundColor: colors.surface2, borderColor: colors.line },
  danger: { backgroundColor: 'rgba(251,113,133,.08)', borderColor: 'rgba(251,113,133,.4)' },
  buttonText: { color: colors.text, fontSize: 16, fontWeight: '700' },
  input: { minHeight: 50, borderRadius: radius.md, borderWidth: 1, borderColor: colors.line, backgroundColor: '#070f1c', color: colors.text, paddingHorizontal: 14, fontSize: 16 },
  error: { color: colors.amber, fontSize: 14, lineHeight: 20 },
  badge: { flexDirection: 'row', alignItems: 'center', alignSelf: 'flex-start', gap: 8, borderWidth: 1, borderRadius: 999, paddingVertical: 6, paddingHorizontal: 12 },
  dot: { width: 8, height: 8, borderRadius: 4 },
  badgeText: { fontSize: 14, fontWeight: '700' },
});
