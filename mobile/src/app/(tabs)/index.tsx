import * as Clipboard from 'expo-clipboard';
import { LinearGradient } from 'expo-linear-gradient';
import { router, useFocusEffect } from 'expo-router';
import { useCallback, useRef, useState } from 'react';
import { Pressable, Text, TextInput, View } from 'react-native';

import { TAB_BAR_SPACE } from '@/components/app-tabs';
import { BrandMark } from '@/components/brand';
import { Icon } from '@/components/icon';
import { Appear, Beam } from '@/components/motion';
import { ToolGrid } from '@/components/tool-grid';
import { Button, ErrorText, Screen, Section, styles as ui } from '@/components/ui';
import { api } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { startUrlScan } from '@/lib/scan';
import { colors, gradients, radius, tone, toneStyle } from '@/lib/theme';
import { findLink } from '@/lib/tools';

function greeting() {
  const h = new Date().getHours();
  return h < 12 ? 'Good morning' : h < 18 ? 'Good afternoon' : 'Good evening';
}

type Recent = { id: number; url: string; verdict: string; date: string }[];

export default function Home() {
  const { user } = useAuth();
  const [url, setUrl] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recent, setRecent] = useState<Recent | null>(null);
  const [heroHeight, setHeroHeight] = useState(0);
  const input = useRef<TextInput>(null);

  useFocusEffect(useCallback(() => {
    api.recent().then((d) => setRecent(d.scans)).catch(() => {});
  }, []));

  async function scan(target = url) {
    if (!target.trim()) return;
    setBusy(true); setError(null);
    try {
      await startUrlScan(target);
      setUrl('');
    } catch (e: any) {
      setError(e.message);
    } finally { setBusy(false); }
  }

  async function paste() {
    const text = await Clipboard.getStringAsync().catch(() => '');
    const link = findLink(text) ?? text.trim();
    if (link) setUrl(link);
    else setError('Your clipboard has no link to paste.');
  }

  const today = new Date().toISOString().slice(0, 10);
  const scansToday = recent?.filter((r) => r.date.startsWith(today)).length;
  const threats = recent?.filter((r) => tone(r.verdict) === 'risk').length;
  const ai = user?.allowance.find((a) => a.service === 'ai_assistant');
  const stats = [
    { value: scansToday, label: 'Scans today', color: colors.text },
    { value: threats, label: 'Risky links found', color: threats ? colors.red : colors.text },
    { value: ai ? (ai.limit === null ? '∞' : `${ai.remaining}/${ai.limit}`) : undefined, label: 'AI answers left', color: colors.text },
  ];

  return (
    <Screen bottom={TAB_BAR_SPACE}>
      <View style={{ flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' }}>
        <View style={{ flexDirection: 'row', alignItems: 'center', gap: 8 }}>
          <BrandMark size={30} />
          <Text style={{ color: colors.text, fontSize: 19, fontWeight: '800' }}>My<Text style={{ color: colors.cyan }}>Scanner</Text></Text>
        </View>
        <Pressable accessibilityRole="button" accessibilityLabel="Account" onPress={() => router.navigate('/account')}>
          <LinearGradient colors={['#1f6f99', '#6d28d9']} style={{ width: 38, height: 38, borderRadius: 19, alignItems: 'center', justifyContent: 'center' }}>
            <Text style={{ color: '#fff', fontWeight: '800' }}>{(user?.username || '?')[0].toUpperCase()}</Text>
          </LinearGradient>
        </Pressable>
      </View>

      <Appear>
        <Text style={[ui.title, { marginTop: 6 }]}>{`${greeting()}, ${user?.username ?? ''}`}</Text>
        <Text style={ui.muted}>What do you want to check?</Text>
      </Appear>

      <Appear delay={80}>
        <View onLayout={(e) => setHeroHeight(e.nativeEvent.layout.height)}
          style={{ borderRadius: radius.xl, borderWidth: 1, borderColor: '#2a4a6a', overflow: 'hidden' }}>
          <LinearGradient colors={gradients.card} style={{ padding: 16, gap: 12 }}>
            {heroHeight ? <Beam height={heroHeight} /> : null}
            <View style={[ui.inputWrap, { backgroundColor: colors.input }]}>
              <Icon name="link" size={19} color={colors.faint} />
              <TextInput ref={input} value={url} onChangeText={setUrl} placeholder="Paste a link to check…" placeholderTextColor={colors.faint}
                style={ui.input} autoCapitalize="none" autoCorrect={false} keyboardType="url" returnKeyType="go" onSubmitEditing={() => scan()} />
              <Pressable accessibilityRole="button" accessibilityLabel="Paste from clipboard" onPress={paste} hitSlop={6}>
                <LinearGradient colors={gradients.accent} style={{ width: 38, height: 38, borderRadius: 12, alignItems: 'center', justifyContent: 'center' }}>
                  <Icon name="paste" size={19} color={colors.onAccent} />
                </LinearGradient>
              </Pressable>
            </View>
            <View style={{ flexDirection: 'row', gap: 10 }}>
              <Button label="Scan link" icon="shield" onPress={() => scan()} busy={busy} disabled={!url.trim()} flex={1} />
              <Button label="QR" icon="qr" kind="secondary" onPress={() => router.push('/qr')} flex={0.5} />
            </View>
            <ErrorText>{error}</ErrorText>
          </LinearGradient>
        </View>
      </Appear>

      <Appear delay={160}>
        <View style={{ flexDirection: 'row', gap: 10 }}>
          {stats.map((s) => (
            <View key={s.label} style={{ flex: 1, padding: 12, borderRadius: 16, backgroundColor: colors.surface, borderWidth: 1, borderColor: colors.line }}>
              <Text style={{ color: s.color, fontSize: 21, fontWeight: '800' }}>{s.value ?? '—'}</Text>
              <Text style={{ color: colors.faint, fontSize: 12, marginTop: 2 }}>{s.label}</Text>
            </View>
          ))}
        </View>
      </Appear>

      <Appear delay={240}>
        <View style={{ gap: 14 }}>
          <Section>All tools</Section>
          <ToolGrid onUrl={() => input.current?.focus()} />
        </View>
      </Appear>

      {recent && recent.length ? (
        <Appear delay={320}>
          <View style={{ gap: 10 }}>
            <Section right={<Pressable onPress={() => router.navigate('/history')}><Text style={{ color: colors.cyanSoft, fontWeight: '700' }}>See all</Text></Pressable>}>
              Recent
            </Section>
            {recent.slice(0, 3).map((r) => {
              const t = toneStyle[tone(r.verdict)];
              return (
                <Pressable key={r.id} onPress={() => router.push({ pathname: '/scan/[id]', params: { id: String(r.id) } })}
                  style={({ pressed }) => ({ flexDirection: 'row', alignItems: 'center', gap: 12, padding: 14, borderRadius: 16,
                    backgroundColor: pressed ? colors.surface2 : colors.surface, borderWidth: 1, borderColor: colors.line })}>
                  <View style={{ width: 10, height: 10, borderRadius: 5, backgroundColor: t.color }} />
                  <Text numberOfLines={1} style={{ flex: 1, color: colors.text, fontSize: 14.5, fontWeight: '600' }}>{r.url}</Text>
                  <Icon name="chevron" size={18} color={colors.faint} />
                </Pressable>
              );
            })}
          </View>
        </Appear>
      ) : null}
    </Screen>
  );
}
