import * as Haptics from 'expo-haptics';
import { LinearGradient } from 'expo-linear-gradient';
import { router, Tabs } from 'expo-router';
import type { ComponentProps } from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Icon, type IconName } from '@/components/icon';
import { colors, gradients } from '@/lib/theme';

type BottomTabBarProps = Parameters<NonNullable<ComponentProps<typeof Tabs>['tabBar']>>[0];

const ICONS: Record<string, { icon: IconName; label: string }> = {
  index: { icon: 'home', label: 'Home' },
  history: { icon: 'clock', label: 'History' },
  assistant: { icon: 'spark', label: 'Assistant' },
  account: { icon: 'user', label: 'Account' },
};

/** Floating glass tab bar with the QR scanner in the middle. */
function TabBar({ state, navigation }: BottomTabBarProps) {
  const insets = useSafeAreaInsets();
  const tabs = state.routes.map((route, index) => {
    const meta = ICONS[route.name];
    if (!meta) return null;
    const focused = state.index === index;
    return (
      <Pressable key={route.key} accessibilityRole="tab" accessibilityState={{ selected: focused }} accessibilityLabel={meta.label}
        style={styles.tab} onPress={() => {
          const event = navigation.emit({ type: 'tabPress', target: route.key, canPreventDefault: true });
          if (!focused && !event.defaultPrevented) {
            Haptics.selectionAsync().catch(() => {});
            navigation.navigate(route.name);
          }
        }}>
        <Icon name={meta.icon} size={23} color={focused ? colors.cyanSoft : colors.faint} />
        <Text style={[styles.label, focused && { color: colors.cyanSoft }]}>{meta.label}</Text>
      </Pressable>
    );
  });
  const scanner = (
    <Pressable key="qr" accessibilityRole="button" accessibilityLabel="Scan a QR code" style={styles.fabWrap}
      onPress={() => { Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium).catch(() => {}); router.push('/qr'); }}>
      <LinearGradient colors={gradients.accent} start={{ x: 0, y: 0 }} end={{ x: 1, y: 1 }} style={styles.fab}>
        <Icon name="qr" size={26} color={colors.onAccent} />
      </LinearGradient>
    </Pressable>
  );
  return (
    <View pointerEvents="box-none" style={[styles.wrap, { bottom: Math.max(insets.bottom, 10) + 4 }]}>
      <View style={styles.bar}>{[...tabs.slice(0, 2), scanner, ...tabs.slice(2)]}</View>
    </View>
  );
}

export default function AppTabs() {
  return (
    <Tabs tabBar={(props) => <TabBar {...props} />} screenOptions={{ headerShown: false, sceneStyle: { backgroundColor: colors.bg } }}>
      <Tabs.Screen name="index" />
      <Tabs.Screen name="history" />
      <Tabs.Screen name="assistant" />
      <Tabs.Screen name="account" />
    </Tabs>
  );
}

/** Space screens leave at the bottom so content clears the floating bar. */
export const TAB_BAR_SPACE = 110;

const styles = StyleSheet.create({
  wrap: { position: 'absolute', left: 14, right: 14 },
  bar: { height: 72, borderRadius: 26, flexDirection: 'row', alignItems: 'center', justifyContent: 'space-around',
    backgroundColor: 'rgba(13,24,40,.96)', borderWidth: 1, borderColor: '#24405c',
    shadowColor: '#000', shadowOpacity: 0.6, shadowRadius: 20, shadowOffset: { width: 0, height: 12 }, elevation: 16 },
  tab: { flex: 1, alignItems: 'center', gap: 3, paddingVertical: 8 },
  label: { fontSize: 11, color: colors.faint, fontWeight: '600' },
  fabWrap: { marginTop: -34 },
  fab: { width: 62, height: 62, borderRadius: 21, alignItems: 'center', justifyContent: 'center', borderWidth: 4, borderColor: colors.bg,
    shadowColor: colors.cyan, shadowOpacity: 0.55, shadowRadius: 16, shadowOffset: { width: 0, height: 8 }, elevation: 10 },
});
