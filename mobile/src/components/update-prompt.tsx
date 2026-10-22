/**
 * In-app update prompts (see lib/update.ts): a full screen when this build is
 * no longer supported, and a card that can be put off when a newer one is out.
 */
import { LinearGradient } from 'expo-linear-gradient';
import { StyleSheet, Text, View } from 'react-native';
import Animated, { FadeIn, FadeInDown, FadeOutDown } from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { BrandMark } from '@/components/brand';
import { Icon } from '@/components/icon';
import { enter, Pulse } from '@/components/motion';
import { NetworkLayer } from '@/components/network-background';
import { Button } from '@/components/ui';
import { t, upper } from '@/lib/i18n';
import { colors, fonts, gradients, radius } from '@/lib/theme';
import { VERSION } from '@/lib/update';

const points = () => [t('The latest security checks'), t('Your reports stay saved'), t('Takes less than a minute')];

/** Shown instead of the app until it is updated. */
export function UpdateRequired({ onUpdate }: { onUpdate: () => void }) {
  const insets = useSafeAreaInsets();
  return (
    <View style={[s.screen, { paddingTop: insets.top + 24, paddingBottom: insets.bottom + 24 }]}>
      <NetworkLayer focused />
      <View style={s.middle}>
        <Animated.View entering={FadeIn.duration(600)}>
          <Pulse size={132}>
            <LinearGradient colors={['#13263b', '#0b1626']} style={s.tile}>
              <BrandMark size={74} />
            </LinearGradient>
            <View style={s.badge}><Icon name="refresh" size={16} color={colors.onAccent} stroke={2.4} /></View>
          </Pulse>
        </Animated.View>
        <Animated.Text entering={enter(1)} style={s.eyebrow}>{upper(t('Update required'))}</Animated.Text>
        <Animated.Text entering={enter(2)} style={s.title}>{t('A new version of MyScanner is ready')}</Animated.Text>
        <Animated.Text entering={enter(3)} style={s.body}>
          {t('This version is no longer supported. Update to keep checking links, files and emails with the latest protection.')}
        </Animated.Text>
        <Animated.View entering={enter(4)} style={s.points}>
          {points().map((point) => (
            <View key={point} style={s.point}>
              <View style={s.check}><Icon name="check" size={13} color={colors.teal} stroke={2.6} /></View>
              <Text style={s.pointText}>{point}</Text>
            </View>
          ))}
        </Animated.View>
      </View>
      <Animated.View entering={enter(5)} style={{ gap: 12 }}>
        <Button label={t('Update now')} arrow="→" onPress={onUpdate} />
        {VERSION ? <Text style={s.version}>{t('You have version {version}', { version: VERSION })}</Text> : null}
      </Animated.View>
    </View>
  );
}

/** A card above the tab bar offering a newer version; "Later" hides it until the next one. */
export function UpdateCard({ onUpdate, onLater }: { onUpdate: () => void; onLater: () => void }) {
  const insets = useSafeAreaInsets();
  return (
    <Animated.View entering={FadeInDown.delay(900).duration(500)} exiting={FadeOutDown.duration(250)}
      style={[s.cardWrap, { bottom: insets.bottom + 92 }]}>
      <LinearGradient colors={gradients.ai} start={{ x: 0, y: 0 }} end={{ x: 1, y: 1 }} style={s.cardBorder}>
        <View style={s.card}>
          <View style={s.cardTop}>
            <View style={s.cardIcon}><Icon name="refresh" size={20} color={colors.cyan} /></View>
            <View style={{ flex: 1, gap: 3 }}>
              <Text style={s.cardTitle}>{t('Update available')}</Text>
              <Text style={s.cardText}>{t('A new version of MyScanner is ready with the latest improvements.')}</Text>
            </View>
          </View>
          <View style={s.cardButtons}>
            <Button label={t('Later')} kind="secondary" flex={1} onPress={onLater} />
            <Button label={t('Update')} flex={1} onPress={onUpdate} />
          </View>
        </View>
      </LinearGradient>
    </Animated.View>
  );
}

const s = StyleSheet.create({
  screen: { flex: 1, backgroundColor: colors.bg, paddingHorizontal: 24 },
  middle: { flex: 1, alignItems: 'center', justifyContent: 'center', gap: 14 },
  tile: { width: 108, height: 108, borderRadius: 32, alignItems: 'center', justifyContent: 'center', borderWidth: 1, borderColor: 'rgba(119,220,255,.28)' },
  badge: { position: 'absolute', right: 6, bottom: 6, width: 30, height: 30, borderRadius: 15, backgroundColor: colors.teal,
           alignItems: 'center', justifyContent: 'center', borderWidth: 3, borderColor: colors.bg },
  eyebrow: { color: colors.cyan, fontFamily: fonts.mono, fontSize: 12, letterSpacing: 2.4, marginTop: 18 },
  title: { color: colors.text, fontFamily: fonts.bold, fontSize: 28, lineHeight: 34, letterSpacing: -0.8, textAlign: 'center' },
  body: { color: colors.soft, fontFamily: fonts.regular, fontSize: 15, lineHeight: 23, textAlign: 'center', maxWidth: 360 },
  points: { alignSelf: 'stretch', gap: 10, marginTop: 10, padding: 16, borderRadius: radius.lg, backgroundColor: 'rgba(16,27,43,.82)',
            borderWidth: 1, borderColor: colors.line },
  point: { flexDirection: 'row', alignItems: 'center', gap: 10 },
  check: { width: 22, height: 22, borderRadius: 11, alignItems: 'center', justifyContent: 'center', backgroundColor: 'rgba(94,234,212,.12)' },
  pointText: { color: colors.text, fontFamily: fonts.medium, fontSize: 14.5 },
  version: { color: colors.faint, fontFamily: fonts.mono, fontSize: 11.5, textAlign: 'center' },
  cardWrap: { position: 'absolute', left: 14, right: 14 },
  cardBorder: { borderRadius: radius.lg, padding: 1.2, shadowColor: '#000', shadowOpacity: 0.5, shadowRadius: 18, elevation: 12 },
  card: { borderRadius: radius.lg - 1, backgroundColor: '#0d1828', padding: 16, gap: 14 },
  cardTop: { flexDirection: 'row', gap: 12, alignItems: 'center' },
  cardIcon: { width: 42, height: 42, borderRadius: 13, alignItems: 'center', justifyContent: 'center', backgroundColor: 'rgba(119,220,255,.1)',
              borderWidth: 1, borderColor: 'rgba(119,220,255,.25)' },
  cardTitle: { color: colors.text, fontFamily: fonts.bold, fontSize: 16 },
  cardText: { color: colors.soft, fontFamily: fonts.regular, fontSize: 13.5, lineHeight: 19 },
  cardButtons: { flexDirection: 'row', gap: 10 },
});
