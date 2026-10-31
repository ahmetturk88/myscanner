/**
 * The one-time card that offers safety reminders (lib/reminders.ts). The system permission dialog
 * only appears after "Turn on reminders" is tapped, so nobody is asked without knowing why.
 */
import { LinearGradient } from 'expo-linear-gradient';
import { useState } from 'react';
import { StyleSheet, Text, View } from 'react-native';
import Animated, { FadeIn, FadeInDown, FadeOut, FadeOutDown } from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Icon } from '@/components/icon';
import { Pulse } from '@/components/motion';
import { Button } from '@/components/ui';
import { t, upper } from '@/lib/i18n';
import { setReminders } from '@/lib/reminders';
import { updateSettings } from '@/lib/settings';
import { colors, fonts, gradients, radius } from '@/lib/theme';

const points = () => [
  { icon: 'clock' as const, text: t('Three short tips a day: morning, afternoon and evening. Never at night.') },
  { icon: 'shield' as const, text: t('Made on your phone: nothing about you or your scans is in them.') },
  { icon: 'settings' as const, text: t('Turn them off any time in Settings.') },
];

export function ReminderPrompt({ onDone }: { onDone: () => void }) {
  const insets = useSafeAreaInsets();
  const [busy, setBusy] = useState(false);
  const [blocked, setBlocked] = useState(false);
  const turnOn = async () => {
    setBusy(true);
    try {
      const on = await setReminders(true);
      if (on) onDone(); else setBlocked(true);
    } catch {
      setBlocked(true);
    } finally {
      setBusy(false);
    }
  };
  const later = () => { updateSettings({ remindersAsked: true }); onDone(); };
  return (
    <Animated.View entering={FadeIn.duration(250)} exiting={FadeOut.duration(200)} style={s.backdrop}>
      <Animated.View entering={FadeInDown.delay(150).duration(450)} exiting={FadeOutDown.duration(200)}
        style={[s.wrap, { paddingBottom: insets.bottom + 18 }]}>
        <LinearGradient colors={gradients.ai} start={{ x: 0, y: 0 }} end={{ x: 1, y: 1 }} style={s.border}>
          <View style={s.card}>
            <View style={{ alignItems: 'center', paddingTop: 6 }}>
              <Pulse size={86}>
                <LinearGradient colors={['#13263b', '#0b1626']} style={s.tile}>
                  <Icon name="bell" size={34} color={colors.cyan} stroke={1.9} />
                </LinearGradient>
              </Pulse>
            </View>
            <Text style={s.eyebrow}>{upper(t('Safety reminders'))}</Text>
            <Text style={s.title}>{t('Stay one step ahead of scams')}</Text>
            <Text style={s.body}>{t('Get a short, useful reminder to check links, files and messages before you trust them.')}</Text>
            <View style={s.points}>
              {points().map((point) => (
                <View key={point.text} style={s.point}>
                  <View style={s.pointIcon}><Icon name={point.icon} size={15} color={colors.teal} stroke={2.2} /></View>
                  <Text style={s.pointText}>{point.text}</Text>
                </View>
              ))}
            </View>
            {blocked ? (
              <Text style={s.blocked}>{t('Notifications are off for MyScanner. You can allow them in your phone’s settings, then turn reminders on in Settings.')}</Text>
            ) : null}
            <View style={{ gap: 10 }}>
              {blocked ? <Button label={t('Close')} onPress={later} />
                : <Button label={t('Turn on reminders')} icon="bell" busy={busy} onPress={turnOn} />}
              {!blocked ? <Button label={t('Not now')} kind="secondary" onPress={later} /> : null}
            </View>
          </View>
        </LinearGradient>
      </Animated.View>
    </Animated.View>
  );
}

const s = StyleSheet.create({
  backdrop: { position: 'absolute', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(2,6,14,.72)', justifyContent: 'flex-end' },
  wrap: { paddingHorizontal: 14 },
  border: { borderRadius: radius.lg + 4, padding: 1.2, shadowColor: '#000', shadowOpacity: 0.55, shadowRadius: 22, elevation: 16 },
  card: { borderRadius: radius.lg + 3, backgroundColor: '#0d1828', padding: 20, gap: 14 },
  tile: { width: 70, height: 70, borderRadius: 22, alignItems: 'center', justifyContent: 'center', borderWidth: 1, borderColor: 'rgba(119,220,255,.28)' },
  eyebrow: { color: colors.cyan, fontFamily: fonts.mono, fontSize: 11.5, letterSpacing: 2.2, textAlign: 'center', marginTop: 4 },
  title: { color: colors.text, fontFamily: fonts.bold, fontSize: 24, lineHeight: 30, letterSpacing: -0.6, textAlign: 'center' },
  body: { color: colors.soft, fontFamily: fonts.regular, fontSize: 14.5, lineHeight: 22, textAlign: 'center' },
  points: { gap: 11, padding: 14, borderRadius: radius.md, backgroundColor: 'rgba(16,27,43,.82)', borderWidth: 1, borderColor: colors.line },
  point: { flexDirection: 'row', alignItems: 'center', gap: 11 },
  pointIcon: { width: 28, height: 28, borderRadius: 9, alignItems: 'center', justifyContent: 'center', backgroundColor: 'rgba(94,234,212,.1)' },
  pointText: { flex: 1, color: colors.text, fontFamily: fonts.medium, fontSize: 13.5, lineHeight: 19 },
  blocked: { color: colors.amber, fontFamily: fonts.regular, fontSize: 13, lineHeight: 19, textAlign: 'center' },
});
