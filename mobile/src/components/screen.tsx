/**
 * The app's screen frame: a large title that hands over to a compact bar as
 * you scroll, a drifting background glow, pull to refresh, and room for the tab bar.
 */
import { router } from 'expo-router';
import { useEffect, useState, type ReactNode } from 'react';
import { Keyboard, Platform, RefreshControl, StyleSheet, Text, View } from 'react-native';
import Animated, { Extrapolation, FadeIn, interpolate, useAnimatedScrollHandler, useAnimatedStyle, useSharedValue } from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Icon } from '@/components/icon';
import { Ambient, PressableScale } from '@/components/motion';
import { colors, fonts } from '@/lib/theme';
import type { Tool } from '@/lib/tools';

/** Space the floating tab bar takes at the bottom of tab screens. */
export const TAB_SPACE = 104;

export function openTool(tool: Tool) {
  if (tool.route === 'url') router.navigate('/');
  else if (tool.route) router.push(tool.route);
  else router.push({ pathname: '/tool/[name]', params: { name: tool.name } });
}

export function useKeyboardVisible() {
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    const show = Keyboard.addListener(Platform.OS === 'ios' ? 'keyboardWillShow' : 'keyboardDidShow', () => setVisible(true));
    const hide = Keyboard.addListener(Platform.OS === 'ios' ? 'keyboardWillHide' : 'keyboardDidHide', () => setVisible(false));
    return () => { show.remove(); hide.remove(); };
  }, []);
  return visible;
}

export function BackButton() {
  return (
    <PressableScale accessibilityLabel="Back" onPress={() => (router.canGoBack() ? router.back() : router.navigate('/'))} style={s.round}>
      <Icon name="back" size={20} color={colors.text} />
    </PressableScale>
  );
}

type Props = {
  title: string; eyebrow?: string; subtitle?: string; back?: boolean; right?: ReactNode; children: ReactNode;
  tabs?: boolean; onRefresh?: () => Promise<unknown> | void; hero?: ReactNode; gap?: number;
  /** Replaces the large title text (the compact bar still shows `title`). */
  largeTitle?: ReactNode; badge?: ReactNode;
};

export function Screen({ title, eyebrow, subtitle, back, right, children, tabs = false, onRefresh, hero, gap = 18, largeTitle, badge }: Props) {
  const insets = useSafeAreaInsets();
  const y = useSharedValue(0);
  const [refreshing, setRefreshing] = useState(false);
  const onScroll = useAnimatedScrollHandler((e) => { y.value = e.contentOffset.y; });
  const bar = useAnimatedStyle(() => ({ opacity: interpolate(y.value, [30, 80], [0, 1], Extrapolation.CLAMP) }));
  const compactTitle = useAnimatedStyle(() => ({
    opacity: interpolate(y.value, [50, 90], [0, 1], Extrapolation.CLAMP),
    transform: [{ translateY: interpolate(y.value, [50, 90], [8, 0], Extrapolation.CLAMP) }],
  }));
  const big = useAnimatedStyle(() => ({
    opacity: interpolate(y.value, [0, 70], [1, 0], Extrapolation.CLAMP),
    transform: [{ scale: interpolate(y.value, [-120, 0], [1.12, 1], Extrapolation.CLAMP) }, { translateY: interpolate(y.value, [0, 80], [0, -10], Extrapolation.CLAMP) }],
  }));

  async function refresh() {
    if (!onRefresh) return;
    setRefreshing(true);
    try { await onRefresh(); } finally { setRefreshing(false); }
  }

  const top = insets.top + 56;
  return (
    <View style={{ flex: 1, backgroundColor: colors.bg }}>
      <Ambient />
      <Animated.ScrollView onScroll={onScroll} scrollEventThrottle={16} keyboardShouldPersistTaps="handled" showsVerticalScrollIndicator={false}
        contentContainerStyle={{ paddingTop: top, paddingHorizontal: 18, paddingBottom: (tabs ? TAB_SPACE : 30) + insets.bottom, gap }}
        refreshControl={onRefresh ? <RefreshControl refreshing={refreshing} onRefresh={refresh} tintColor={colors.cyan} colors={[colors.cyan]}
          progressBackgroundColor="#10233a" progressViewOffset={top} /> : undefined}>
        <Animated.View style={[{ gap: 6, transformOrigin: 'left' }, big]} entering={FadeIn.duration(400)}>
          {badge}
          {eyebrow ? <Text style={s.eyebrow}>{eyebrow.toUpperCase()}</Text> : null}
          <Text style={s.title}>{largeTitle ?? title}</Text>
          {subtitle ? <Text style={s.subtitle}>{subtitle}</Text> : null}
        </Animated.View>
        {hero}
        {children}
      </Animated.ScrollView>
      <View style={[s.header, { paddingTop: insets.top, height: top }]} pointerEvents="box-none">
        <Animated.View style={[StyleSheet.absoluteFill, s.headerBg, bar]} />
        {back ? <BackButton /> : <View style={{ width: 4 }} />}
        <Animated.Text numberOfLines={1} style={[s.compact, compactTitle]}>{title}</Animated.Text>
        <View style={{ marginLeft: 'auto', flexDirection: 'row', gap: 8 }}>{right}</View>
      </View>
    </View>
  );
}

const s = StyleSheet.create({
  header: { position: 'absolute', left: 0, right: 0, top: 0, flexDirection: 'row', alignItems: 'center', gap: 12, paddingHorizontal: 14 },
  headerBg: { backgroundColor: 'rgba(7,11,20,.94)', borderBottomWidth: 1, borderBottomColor: 'rgba(145,188,220,.14)' },
  compact: { color: colors.text, fontSize: 17, fontFamily: fonts.bold, flexShrink: 1 },
  round: { width: 40, height: 40, borderRadius: 20, alignItems: 'center', justifyContent: 'center', backgroundColor: 'rgba(17,35,56,.85)', borderWidth: 1, borderColor: '#2b4560' },
  eyebrow: { color: colors.cyan, fontFamily: fonts.mono, fontSize: 12, letterSpacing: 2 },
  title: { color: colors.text, fontFamily: fonts.bold, fontSize: 32, lineHeight: 37, letterSpacing: -1.1 },
  subtitle: { color: colors.soft, fontFamily: fonts.regular, fontSize: 15, lineHeight: 23 },
});
