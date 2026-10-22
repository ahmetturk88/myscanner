import * as Clipboard from 'expo-clipboard';
import { LinearGradient } from 'expo-linear-gradient';
import { router, useFocusEffect } from 'expo-router';
import { useCallback, useRef, useState } from 'react';
import { StyleSheet, Text, TextInput, View } from 'react-native';
import Animated from 'react-native-reanimated';

import { Empty, ReportRow, SectionHead, ToolTile, type Report } from '@/components/blocks';
import { Icon, type IconName } from '@/components/icon';
import { Beam, enter, PressableScale, useCountUp } from '@/components/motion';
import { Screen } from '@/components/screen';
import { Accent } from '@/components/tool-hero';
import { Button, ErrorText, Skeleton, styles as ui } from '@/components/ui';
import { api } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { t } from '@/lib/i18n';
import { startUrlScan } from '@/lib/scan';
import { colors, fonts, gradients, tone } from '@/lib/theme';
import { findLink, toolByName, tools } from '@/lib/tools';

const quick = (): [string, IconName, string][] => [['qr', 'qr', t('QR code')], ['file', 'file', t('File')], ['email', 'mail', t('Email')], ['password', 'key', t('Password')]];

function greeting() {
  const h = new Date().getHours();
  return h < 5 ? t('Good night') : h < 12 ? t('Good morning') : h < 18 ? t('Good afternoon') : t('Good evening');
}

function Stat({ label, value, color }: { label: string; value?: number; color: string }) {
  const n = useCountUp(value);
  return (
    <View style={s.stat}>
      <Text style={{ color, fontSize: 24, fontFamily: fonts.bold }}>{n ?? '—'}</Text>
      <Text style={{ color: colors.muted, fontSize: 12, fontFamily: fonts.medium }}>{label}</Text>
    </View>
  );
}

export default function Home() {
  const { user } = useAuth();
  const [url, setUrl] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recent, setRecent] = useState<Report[] | null>(null);
  const [cardHeight, setCardHeight] = useState(0);
  const input = useRef<TextInput>(null);

  const load = useCallback(() => api.recent().then((d) => setRecent(d.scans)).catch(() => {}), []);
  useFocusEffect(useCallback(() => { load(); }, [load]));

  async function scan() {
    if (!url.trim()) { input.current?.focus(); return; }
    setBusy(true); setError(null);
    try { await startUrlScan(url); setUrl(''); } catch (e: any) { setError(e.message); } finally { setBusy(false); }
  }

  async function paste() {
    const text = await Clipboard.getStringAsync().catch(() => '');
    const link = findLink(text) ?? text.trim();
    if (link) { setUrl(link); setError(null); } else setError(t('Your clipboard has no link to paste.'));
  }

  const avatar = (
    <PressableScale accessibilityLabel={t('Account')} onPress={() => router.navigate('/account')}>
      <LinearGradient colors={gradients.ai} style={s.avatarRing}>
        <View style={s.avatar}><Text style={{ color: '#fff', fontFamily: fonts.bold, fontSize: 15 }}>{(user?.username || '?')[0].toUpperCase()}</Text></View>
      </LinearGradient>
    </PressableScale>
  );

  return (
    <Screen tabs eyebrow={greeting()} title={t('Hi, {name}', { name: user?.username ?? '' })} right={avatar} onRefresh={load}
      subtitle={t('What would you like to check today?')}>
      <Animated.View entering={enter(1)}>
        <LinearGradient colors={['#123049', '#0d1a2b', '#0a1f2c']} locations={[0, 0.55, 1]} start={{ x: 0, y: 0 }} end={{ x: 1, y: 1 }}
          style={s.hero} onLayout={(e) => setCardHeight(e.nativeEvent.layout.height)}>
          {cardHeight ? <Beam height={cardHeight} /> : null}
          <View style={{ flexDirection: 'row', alignItems: 'center', gap: 8 }}>
            <Icon name="link" size={15} color={colors.cyan} />
            <Text style={s.kicker}>{t('URL SCANNER')}</Text>
          </View>
          <Text style={s.heroTitle}><Accent text={t("What's behind this link?")} accent={t('this link?')} /></Text>
          <View style={ui.inputWrap}>
            <Icon name="link" size={17} color={colors.faint} />
            <TextInput ref={input} value={url} onChangeText={setUrl} placeholder={t('Paste or type a link')} placeholderTextColor="#5f7590"
              style={ui.input} autoCapitalize="none" autoCorrect={false} keyboardType="url" returnKeyType="go" onSubmitEditing={scan} />
            <PressableScale accessibilityLabel={t('Paste from clipboard')} onPress={paste} style={s.paste}>
              <Icon name="paste" size={17} color={colors.cyan} />
            </PressableScale>
          </View>
          <Button label={t('Scan link')} arrow="→" onPress={scan} busy={busy} />
          <ErrorText>{error}</ErrorText>
        </LinearGradient>
      </Animated.View>

      <View style={{ flexDirection: 'row', gap: 10 }}>
        {quick().map(([name, icon, label], i) => (
          <Animated.View key={name} entering={enter(i + 2)} style={{ flex: 1 }}>
            <PressableScale accessibilityLabel={label} onPress={() => {
              const tool = toolByName(name)!;
              if (tool.route && tool.route !== 'url') router.push(tool.route); else router.push({ pathname: '/tool/[name]', params: { name } });
            }} style={s.quick}>
              <View style={s.quickIcon}><Icon name={icon} size={21} color={colors.cyan} /></View>
              <Text style={{ color: colors.soft, fontSize: 12.5, fontFamily: fonts.semibold }}>{label}</Text>
            </PressableScale>
          </Animated.View>
        ))}
      </View>

      <SectionHead title={t('Recent reports')} action={recent?.length ? t('See all') : undefined} onAction={() => router.navigate('/history')} />
      {recent?.length ? (
        <Animated.View entering={enter(3)} style={{ flexDirection: 'row', gap: 10 }}>
          <Stat label={t('Reports')} value={recent.length} color={colors.cyan} />
          <Stat label={t('Threats')} value={recent.filter((r) => tone(r.verdict) === 'risk').length} color={colors.red} />
          <Stat label={t('To review')} value={recent.filter((r) => tone(r.verdict) === 'review').length} color={colors.amber} />
        </Animated.View>
      ) : null}
      {!recent ? <View style={{ gap: 10 }}><Skeleton height={70} /><Skeleton height={70} /></View> : null}
      {recent && !recent.length ? <Empty icon="link" title={t('No reports yet')} text={t('Scan your first link above. Every report is saved here.')} /> : null}
      <View style={{ gap: 10 }}>
        {(recent ?? []).slice(0, 4).map((r, i) => <ReportRow key={r.id} report={r} index={i} />)}
      </View>

      <SectionHead title={t('All tools')} />
      <View style={{ flexDirection: 'row', flexWrap: 'wrap', gap: 12 }}>
        {tools().filter((tool) => tool.route !== 'url').map((tool, i) => <ToolTile key={tool.name} tool={tool} index={i} />)}
      </View>
    </Screen>
  );
}

const s = StyleSheet.create({
  avatarRing: { width: 42, height: 42, borderRadius: 21, padding: 2 },
  avatar: { flex: 1, borderRadius: 20, backgroundColor: '#0d1726', alignItems: 'center', justifyContent: 'center' },
  hero: { borderRadius: 26, borderWidth: 1, borderColor: 'rgba(119,220,255,.22)', padding: 20, gap: 14, overflow: 'hidden' },
  kicker: { color: colors.cyan, fontFamily: fonts.mono, fontSize: 12, letterSpacing: 2 },
  heroTitle: { color: colors.text, fontFamily: fonts.bold, fontSize: 27, lineHeight: 32, letterSpacing: -0.9 },
  paste: { width: 38, height: 38, borderRadius: 11, alignItems: 'center', justifyContent: 'center', backgroundColor: 'rgba(119,220,255,.1)', borderWidth: 1, borderColor: 'rgba(119,220,255,.3)' },
  quick: { alignItems: 'center', gap: 8, paddingVertical: 14, borderRadius: 20, borderWidth: 1, borderColor: colors.line, backgroundColor: '#0e1825' },
  quickIcon: { width: 44, height: 44, borderRadius: 15, alignItems: 'center', justifyContent: 'center', backgroundColor: 'rgba(119,220,255,.08)', borderWidth: 1, borderColor: 'rgba(119,220,255,.2)' },
  stat: { flex: 1, paddingVertical: 12, paddingHorizontal: 14, borderRadius: 16, borderWidth: 1, borderColor: colors.line, backgroundColor: '#0e1825', gap: 2 },
});
