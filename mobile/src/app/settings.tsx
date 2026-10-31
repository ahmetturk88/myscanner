import Constants from 'expo-constants';
import { router } from 'expo-router';
import * as WebBrowser from 'expo-web-browser';
import { Platform, StyleSheet, Switch, Text, View } from 'react-native';

import { Icon, type IconName } from '@/components/icon';
import { PressableScale } from '@/components/motion';
import { Screen } from '@/components/screen';
import { SITE } from '@/lib/api';
import * as Haptics from '@/lib/haptics';
import { lang, t, upper } from '@/lib/i18n';
import { setReminders } from '@/lib/reminders';
import { type Language, updateSettings, useSettings } from '@/lib/settings';
import { colors, fonts } from '@/lib/theme';

const languages = (): { code: Language; name: string; native: string; ready: boolean }[] => [
  { code: 'en', name: t('English'), native: 'English', ready: true },
  { code: 'tr', name: t('Turkish'), native: 'Türkçe', ready: true },
  { code: 'ar', name: t('Arabic'), native: 'العربية', ready: false },
];

/** Switch the language. The app redraws from its first screen, so come back here. */
function choose(code: Language) {
  updateSettings({ language: code });
  setTimeout(() => router.navigate('/settings'), 0);
}

// No entrance animations here: a short, static list opens fastest while the screen slides in.
function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <View style={{ gap: 8 }}>
      <Text style={s.section}>{upper(title)}</Text>
      <View style={s.card}>{children}</View>
    </View>
  );
}

function Toggle({ icon, label, hint, value, onChange, last }: { icon: IconName; label: string; hint: string; value: boolean; onChange: (v: boolean) => void; last?: boolean }) {
  return (
    <View style={[s.row, !last && s.line]}>
      <View style={s.icon}><Icon name={icon} size={17} color={colors.cyan} /></View>
      <View style={{ flex: 1, gap: 2 }}>
        <Text style={s.label}>{label}</Text>
        <Text style={s.hint}>{hint}</Text>
      </View>
      <Switch value={value} onValueChange={(v) => { onChange(v); if (v) Haptics.selectionAsync().catch(() => {}); }}
        trackColor={{ false: '#22344a', true: 'rgba(94,234,212,.55)' }} thumbColor={value ? colors.teal : '#93a7bf'} />
    </View>
  );
}

function Link({ icon, label, path, last }: { icon: IconName; label: string; path: string; last?: boolean }) {
  // Open the page in the app's language (the Turkish privacy page is the KVKK notice).
  return (
    <PressableScale scale={0.98} onPress={() => WebBrowser.openBrowserAsync(`${SITE}${path}?lang=${lang()}`)} style={[s.row, !last && s.line]}>
      <View style={s.icon}><Icon name={icon} size={17} color={colors.cyan} /></View>
      <Text style={[s.label, { flex: 1 }]}>{label}</Text>
      <Icon name="external" size={15} color={colors.faint} />
    </PressableScale>
  );
}

export default function SettingsScreen() {
  const settings = useSettings();
  const LANGUAGES = languages();
  return (
    <Screen back title={t('Settings')} eyebrow={t('Preferences')} largeTitle={t('Settings')} subtitle={t('Saved on this phone only.')}>
      <Section title={t('Language')}>
        {LANGUAGES.map((lang, i) => {
          const selected = settings.language === lang.code;
          return (
            <PressableScale key={lang.code} scale={0.98} disabled={!lang.ready} accessibilityLabel={lang.name}
              onPress={() => { if (!selected) choose(lang.code); }} style={[s.row, i < LANGUAGES.length - 1 && s.line, !lang.ready && { opacity: 0.55 }]}>
              <View style={[s.radio, selected && { borderColor: colors.teal }]}>{selected ? <View style={s.radioDot} /> : null}</View>
              <View style={{ flex: 1, gap: 2 }}>
                <Text style={[s.label, { textAlign: 'left', writingDirection: 'ltr' }]}>{lang.native}</Text>
                {lang.native !== lang.name ? <Text style={s.hint}>{lang.name}</Text> : null}
              </View>
              {!lang.ready ? <View style={s.soon}><Text style={s.soonText}>{t('COMING SOON')}</Text></View> : null}
            </PressableScale>
          );
        })}
      </Section>
      <Text style={[s.hint, { marginTop: -6, paddingHorizontal: 4 }]}>
        {t('Your choice switches the whole app, reports included. Arabic is coming soon. The AI assistant already answers in the language you write in.')}
      </Text>

      <Section title={t('Experience')}>
        <Toggle icon="vibrate" label={t('Vibration')} hint={t('A short buzz when a result arrives and on taps.')}
          value={settings.haptics} onChange={(v) => updateSettings({ haptics: v })} />
        <Toggle icon="code" label={t('Show technical evidence')} hint={t('Open the full evidence under every report by default.')}
          value={settings.evidenceOpen} onChange={(v) => updateSettings({ evidenceOpen: v })} />
        <Toggle icon="spark" label={t('Animated background')} hint={t('Turns off by itself on phones where it is not smooth.')}
          value={settings.backgroundMotion} onChange={(v) => updateSettings({ backgroundMotion: v, motionChecked: true })} last={Platform.OS === 'web'} />
        {Platform.OS !== 'web' ? (
          <Toggle icon="bell" label={t('Safety reminders')} hint={t('Three short tips a day: morning, afternoon and evening. Never at night.')}
            value={settings.reminders} onChange={(v) => { setReminders(v).catch(() => {}); }} last />
        ) : null}
      </Section>

      <Section title={t('About')}>
        <Link icon="shield" label={t('Privacy policy')} path="/privacy" />
        <Link icon="doc" label={t('Terms of service')} path="/terms" />
        <Link icon="mail" label={t('Contact and feedback')} path="/contact" last />
      </Section>
      <View style={{ alignItems: 'center', gap: 4, marginTop: 4 }}>
        <Text style={{ color: colors.soft, fontSize: 13, fontFamily: fonts.semibold }}>MyScanner {Constants.expoConfig?.version ?? ''}</Text>
        <Text style={s.hint}>{t('Made to check before you click.')}</Text>
      </View>
    </Screen>
  );
}

const s = StyleSheet.create({
  section: { color: colors.faint, fontFamily: fonts.mono, fontSize: 11.5, letterSpacing: 1.8, paddingHorizontal: 4 },
  card: { paddingHorizontal: 16, borderRadius: 22, borderWidth: 1, borderColor: colors.line, backgroundColor: '#0e1825' },
  row: { flexDirection: 'row', alignItems: 'center', gap: 12, paddingVertical: 14 },
  line: { borderBottomWidth: 1, borderBottomColor: 'rgba(145,188,220,.1)' },
  icon: { width: 34, height: 34, borderRadius: 11, alignItems: 'center', justifyContent: 'center', backgroundColor: 'rgba(119,220,255,.07)', borderWidth: 1, borderColor: 'rgba(119,220,255,.2)' },
  label: { color: colors.text, fontSize: 15, fontFamily: fonts.medium },
  hint: { color: colors.faint, fontSize: 12.5, lineHeight: 18, fontFamily: fonts.regular },
  radio: { width: 22, height: 22, borderRadius: 11, borderWidth: 2, borderColor: colors.line2, alignItems: 'center', justifyContent: 'center' },
  radioDot: { width: 10, height: 10, borderRadius: 5, backgroundColor: colors.teal },
  soon: { paddingVertical: 4, paddingHorizontal: 8, borderRadius: 999, borderWidth: 1, borderColor: colors.line2 },
  soonText: { color: colors.soft, fontSize: 9.5, letterSpacing: 1, fontFamily: fonts.monoBold },
});
