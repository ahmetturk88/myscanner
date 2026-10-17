import * as Haptics from 'expo-haptics';
import { LinearGradient } from 'expo-linear-gradient';
import { router, type Tabs } from 'expo-router';
import { useEffect, useState, type ComponentProps } from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';
import Animated, { useAnimatedStyle, useSharedValue, withSpring, withTiming } from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Icon, type IconName } from '@/components/icon';
import { PressableScale, Pulse } from '@/components/motion';
import { useKeyboardVisible } from '@/components/screen';
import { colors, fonts, gradients } from '@/lib/theme';

type BarProps = Parameters<NonNullable<ComponentProps<typeof Tabs>['tabBar']>>[0];

const META: Record<string, { icon: IconName; label: string }> = {
  index: { icon: 'home', label: 'Home' },
  history: { icon: 'clock', label: 'History' },
  assistant: { icon: 'spark', label: 'Assistant' },
  account: { icon: 'user', label: 'Account' },
};
// Five slots: two tabs, the scanner button, two tabs.
const SLOT = [0, 1, 3, 4];
const SPRING = { damping: 17, stiffness: 190, mass: 0.8 };

function TabButton({ icon, label, focused, onPress }: { icon: IconName; label: string; focused: boolean; onPress: () => void }) {
  const on = useSharedValue(focused ? 1 : 0);
  useEffect(() => { on.value = withSpring(focused ? 1 : 0, SPRING); }, [focused, on]);
  const iconStyle = useAnimatedStyle(() => ({ transform: [{ translateY: -2 * on.value }, { scale: 1 + 0.12 * on.value }] }));
  return (
    <Pressable accessibilityRole="tab" accessibilityState={{ selected: focused }} accessibilityLabel={label} onPress={onPress} style={s.tab}>
      <Animated.View style={iconStyle}><Icon name={icon} size={22} color={focused ? colors.cyan : colors.faint} /></Animated.View>
      <Text style={[s.label, focused && { color: colors.cyan }]}>{label}</Text>
    </Pressable>
  );
}

/** Floating glass bar; a light pill slides to the active tab, the QR scanner sits in the middle. */
export function TabBar({ state, navigation }: BarProps) {
  const insets = useSafeAreaInsets();
  const keyboard = useKeyboardVisible();
  const [width, setWidth] = useState(0);
  const slot = width / 5;
  const x = useSharedValue(0);
  const hidden = useSharedValue(0);
  useEffect(() => { x.value = withSpring(SLOT[state.index] * slot, SPRING); }, [state.index, slot, x]);
  useEffect(() => { hidden.value = withTiming(keyboard ? 1 : 0, { duration: 180 }); }, [keyboard, hidden]);
  const pill = useAnimatedStyle(() => ({ transform: [{ translateX: x.value }] }));
  const wrap = useAnimatedStyle(() => ({ opacity: 1 - hidden.value, transform: [{ translateY: hidden.value * 120 }] }));

  const tabs = state.routes.map((route, index) => {
    const meta = META[route.name];
    if (!meta) return null;
    const focused = state.index === index;
    return (
      <TabButton key={route.key} icon={meta.icon} label={meta.label} focused={focused} onPress={() => {
        const event = navigation.emit({ type: 'tabPress', target: route.key, canPreventDefault: true });
        if (!focused && !event.defaultPrevented) {
          Haptics.selectionAsync().catch(() => {});
          navigation.navigate(route.name);
        }
      }} />
    );
  });

  return (
    <Animated.View pointerEvents={keyboard ? 'none' : 'box-none'} style={[s.wrap, { bottom: Math.max(insets.bottom, 10) + 6 }, wrap]}>
      <View style={s.bar} onLayout={(e) => setWidth(e.nativeEvent.layout.width)}>
        {width ? (
          <Animated.View style={[s.pillSlot, { width: slot }, pill]}>
            <LinearGradient colors={['rgba(119,220,255,.16)', 'rgba(94,234,212,.08)']} style={s.pill} />
          </Animated.View>
        ) : null}
        {tabs.slice(0, 2)}
        <View style={s.tab}>
          <PressableScale accessibilityLabel="Scan a QR code" scale={0.9} style={s.fabWrap}
            onPress={() => { Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium).catch(() => {}); router.push('/qr'); }}>
            <Pulse size={58} color="rgba(119,220,255,.7)">
              <LinearGradient colors={gradients.accent} start={{ x: 0, y: 0 }} end={{ x: 1, y: 1 }} style={s.fab}>
                <Icon name="qr" size={25} color={colors.onAccent} />
              </LinearGradient>
            </Pulse>
          </PressableScale>
        </View>
        {tabs.slice(2)}
      </View>
    </Animated.View>
  );
}

const s = StyleSheet.create({
  wrap: { position: 'absolute', left: 14, right: 14 },
  bar: { height: 70, borderRadius: 26, flexDirection: 'row', alignItems: 'center',
    backgroundColor: '#0c1625', borderWidth: 1, borderColor: '#23405c', elevation: 14,
    shadowColor: '#000', shadowOpacity: 0.55, shadowRadius: 22, shadowOffset: { width: 0, height: 12 } },
  pillSlot: { position: 'absolute', top: 7, bottom: 7, left: 0, paddingHorizontal: 6 },
  pill: { flex: 1, borderRadius: 19, borderWidth: 1, borderColor: 'rgba(119,220,255,.22)' },
  tab: { flex: 1, alignItems: 'center', justifyContent: 'center', gap: 3, height: '100%' },
  label: { fontSize: 11, color: colors.faint, fontFamily: fonts.semibold },
  fabWrap: { marginTop: -30 },
  fab: { width: 58, height: 58, borderRadius: 20, alignItems: 'center', justifyContent: 'center', borderWidth: 3, borderColor: colors.bg },
});
