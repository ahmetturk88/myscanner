import Constants from 'expo-constants';
import * as WebBrowser from 'expo-web-browser';
import { StyleSheet, Switch, Text, View } from 'react-native';
import Animated from 'react-native-reanimated';

import { Icon, type IconName } from '@/components/icon';
import { enter, PressableScale } from '@/components/motion';
import { Screen } from '@/components/screen';
import { SITE } from '@/lib/api';
import * as Haptics from '@/lib/haptics';
import { type Language, updateSettings, useSettings } from '@/lib/settings';
import { colors, fonts } from '@/lib/theme';

const LANGUAGES: { code: Language; name: string; native: string; ready: boolean }[] = [
  { code: 'en', name: 'English', native: 'English', ready: true },
  { code: 'tr', name: 'Turkish', native: 'Türkçe', ready: false },
  { code: 'ar', name: 'Arabic', native: 'العربية', ready: false },
];

function Section({ title, index, children }: { title: string; index: number; children: React.ReactNode }) {
  return (
    <Animated.View entering={enter(index)} style={{ gap: 8 }}>
      <Text style={s.section}>{title.toUpperCase()}</Text>
      <View style={s.card}>{children}</View>
    </Animated.View>
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
  return (
    <PressableScale scale={0.98} onPress={() => WebBrowser.openBrowserAsync(`${SITE}${path}`)} style={[s.row, !last && s.line]}>
      <View style={s.icon}><Icon name={icon} size={17} color={colors.cyan} /></View>
      <Text style={[s.label, { flex: 1 }]}>{label}</Text>
      <Icon name="external" size={15} color={colors.faint} />
    </PressableScale>
  );
}

export default function SettingsScreen() {
  const settings = useSettings();
  return (
    <Screen back title="Settings" eyebrow="Preferences" largeTitle="Settings" subtitle="Saved on this phone only.">
      <Section title="Language" index={1}>
        {LANGUAGES.map((lang, i) => {
          const selected = settings.language === lang.code;
          return (
            <PressableScale key={lang.code} scale={0.98} disabled={!lang.ready} accessibilityLabel={lang.name}
              onPress={() => updateSettings({ language: lang.code })} style={[s.row, i < LANGUAGES.length - 1 && s.line, !lang.ready && { opacity: 0.55 }]}>
              <View style={[s.radio, selected && { borderColor: colors.teal }]}>{selected ? <View style={s.radioDot} /> : null}</View>
              <View style={{ flex: 1, gap: 2 }}>
                <Text style={[s.label, { textAlign: 'left', writingDirection: 'ltr' }]}>{lang.native}</Text>
                {lang.native !== lang.name ? <Text style={s.hint}>{lang.name}</Text> : null}
              </View>
              {!lang.ready ? <View style={s.soon}><Text style={s.soonText}>COMING SOON</Text></View> : null}
            </PressableScale>
          );
        })}
      </Section>
      <Text style={[s.hint, { marginTop: -6, paddingHorizontal: 4 }]}>
        Turkish and Arabic will switch the whole app, reports included. The AI assistant already answers in the language you write in.
      </Text>

      <Section title="Experience" index={2}>
        <Toggle icon="vibrate" label="Vibration" hint="A short buzz when a result arrives and on taps."
          value={settings.haptics} onChange={(v) => updateSettings({ haptics: v })} />
        <Toggle icon="code" label="Show technical evidence" hint="Open the full evidence under every report by default."
          value={settings.evidenceOpen} onChange={(v) => updateSettings({ evidenceOpen: v })} last />
      </Section>

      <Section title="About" index={3}>
        <Link icon="shield" label="Privacy policy" path="/privacy" />
        <Link icon="doc" label="Terms of service" path="/terms" />
        <Link icon="mail" label="Contact and feedback" path="/contact" last />
      </Section>
      <Animated.View entering={enter(4)} style={{ alignItems: 'center', gap: 4, marginTop: 4 }}>
        <Text style={{ color: colors.soft, fontSize: 13, fontFamily: fonts.semibold }}>MyScanner {Constants.expoConfig?.version ?? ''}</Text>
        <Text style={s.hint}>Made to check before you click.</Text>
      </Animated.View>
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
