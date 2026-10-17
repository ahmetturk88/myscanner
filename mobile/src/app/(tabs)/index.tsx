import * as Clipboard from 'expo-clipboard';
import { LinearGradient } from 'expo-linear-gradient';
import { router, useFocusEffect } from 'expo-router';
import { useCallback, useMemo, useRef, useState } from 'react';
import { Pressable, StyleSheet, Text, TextInput, View } from 'react-native';

import { Icon } from '@/components/icon';
import { Appear, Beam } from '@/components/motion';
import { openTool, Page, ToolRail } from '@/components/site';
import { Button, Chips, ErrorText, Eyebrow, Hero, Lead, styles as ui, VerdictBadge } from '@/components/ui';
import { api } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { startUrlScan } from '@/lib/scan';
import { colors, fonts, tone } from '@/lib/theme';
import { CATEGORIES, TOOLS, findLink } from '@/lib/tools';

type Recent = { id: number; url: string; verdict: string; date: string }[];
const URL_TOOL = TOOLS[0];

export default function Workspace() {
  const { user } = useAuth();
  const [url, setUrl] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recent, setRecent] = useState<Recent | null>(null);
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState<string>('all');
  const [launchHeight, setLaunchHeight] = useState(0);
  const input = useRef<TextInput>(null);

  const load = useCallback(() => { api.recent().then((d) => setRecent(d.scans)).catch(() => {}); }, []);
  useFocusEffect(load);

  async function scan() {
    if (!url.trim()) { input.current?.focus(); return; }
    setBusy(true); setError(null);
    try {
      await startUrlScan(url);
      setUrl('');
    } catch (e: any) {
      setError(e.message);
    } finally { setBusy(false); }
  }

  async function paste() {
    const text = await Clipboard.getStringAsync().catch(() => '');
    const link = findLink(text) ?? text.trim();
    if (link) setUrl(link); else setError('Your clipboard has no link to paste.');
  }

  const tools = useMemo(() => TOOLS.filter((t) => (category === 'all' || t.category === category)
    && `${t.title} ${t.menu}`.toLowerCase().includes(query.trim().toLowerCase())), [query, category]);
  const counts = {
    total: recent?.length,
    threats: recent?.filter((r) => tone(r.verdict) === 'risk').length,
    review: recent?.filter((r) => tone(r.verdict) === 'review').length,
  };

  return (
    <Page>
      <ToolRail active="url" />

      <Appear>
        <View style={{ gap: 12, marginTop: 10 }}>
          <Eyebrow>Your security workspace</Eyebrow>
          <Text style={[ui.hero, { fontSize: 33, lineHeight: 37 }]}>Welcome back, <Text style={{ color: colors.cyan }}>{user?.username ?? ''}.</Text></Text>
          <Lead>Start an investigation. Revisit the evidence. Choose your next move.</Lead>
          <View style={{ alignSelf: 'flex-start' }}>
            <Button kind="secondary" label="Account & reports" arrow="↗" onPress={() => router.navigate('/account')} />
          </View>
        </View>
      </Appear>

      <Appear delay={80}>
        <View style={s.launch} onLayout={(e) => setLaunchHeight(e.nativeEvent.layout.height)}>
          <LinearGradient colors={['rgba(33,86,107,.35)', 'rgba(16,28,44,0)']} start={{ x: 0, y: 1 }} end={{ x: 0.6, y: 0.3 }} style={StyleSheet.absoluteFill} />
          {launchHeight ? <Beam height={launchHeight} /> : null}
          <View style={{ padding: 22, gap: 14 }}>
            <View style={{ flexDirection: 'row', alignItems: 'center', gap: 10 }}>
              <Icon name="link" size={15} color={colors.cyan} />
              <Eyebrow>URL intelligence</Eyebrow>
            </View>
            <Hero title={URL_TOOL.heading} accent={URL_TOOL.accent} size={32} />
            <Lead>{URL_TOOL.lead}</Lead>
            <Chips items={URL_TOOL.chips} />
          </View>
          <View style={{ padding: 22, paddingTop: 4, gap: 12 }}>
            <Text style={ui.label}>URL to investigate</Text>
            <View style={ui.inputWrap}>
              <Icon name="link" size={17} color="#7f93ad" />
              <TextInput ref={input} value={url} onChangeText={setUrl} placeholder="https://example.com" placeholderTextColor="#5f7590"
                style={ui.input} autoCapitalize="none" autoCorrect={false} keyboardType="url" returnKeyType="go" onSubmitEditing={scan} />
              <Pressable accessibilityRole="button" accessibilityLabel="Paste from clipboard" onPress={paste} hitSlop={6} style={s.paste}>
                <Icon name="paste" size={17} color={colors.cyan} />
              </Pressable>
            </View>
            <Text style={{ color: colors.faint, fontSize: 13, fontFamily: fonts.regular }}>HTTP or HTTPS · Public targets only · Use authorized targets</Text>
            <View style={{ flexDirection: 'row', alignItems: 'center', gap: 16, flexWrap: 'wrap' }}>
              <Button label="Analyze URL" arrow="↗" onPress={scan} busy={busy} />
              <Button kind="link" label="Use example URL" onPress={() => setUrl('https://example.com')} />
            </View>
            <Button kind="secondary" icon="qr" label="Scan a QR code with the camera" onPress={() => router.push('/qr')} />
            <ErrorText>{error}</ErrorText>
            <View style={s.note}>
              <Icon name="alert" size={15} color={colors.faint} />
              <Text style={{ flex: 1, color: colors.faint, fontSize: 13, lineHeight: 20, fontFamily: fonts.regular }}>
                A lower score may reflect missing checks. Read the evidence and coverage together.
              </Text>
            </View>
          </View>
        </View>
      </Appear>

      <View style={{ gap: 14, marginTop: 14 }}>
        <Eyebrow>Your toolkit</Eyebrow>
        <Text style={ui.section}>A tool for every question.</Text>
        <View style={ui.inputWrap}>
          <Icon name="search" size={17} color="#7f93ad" />
          <TextInput value={query} onChangeText={setQuery} placeholder="Find a tool…" placeholderTextColor="#5f7590" style={ui.input} autoCorrect={false} />
        </View>
        <View style={{ flexDirection: 'row', flexWrap: 'wrap', gap: 8 }}>
          {CATEGORIES.map((c) => {
            const on = category === c.key;
            return (
              <Pressable key={c.key} onPress={() => setCategory(c.key)} accessibilityState={{ selected: on }}
                style={[s.filter, on && { backgroundColor: '#123a52', borderColor: '#2b7289' }]}>
                <Text style={{ color: on ? '#e6f7ff' : '#a9bbd2', fontSize: 13, fontFamily: fonts.medium }}>{c.key === 'all' ? 'All' : c.label}</Text>
              </Pressable>
            );
          })}
        </View>
        {tools.map((tool, i) => (
          <Appear key={tool.name} delay={Math.min(i, 5) * 50}>
            <Pressable onPress={() => (tool.route === 'url' ? input.current?.focus() : openTool(tool))}
              style={({ pressed }) => [{ transform: [{ translateY: pressed ? -2 : 0 }] }]}>
              <LinearGradient colors={['#121e2d', '#0e1623']} start={{ x: 0, y: 0 }} end={{ x: 1, y: 1 }} style={s.tool}>
                <View style={{ flexDirection: 'row', justifyContent: 'space-between' }}>
                  <View style={s.toolIcon}><Icon name={tool.icon} size={19} color={colors.cyan} /></View>
                  <Text style={{ color: '#6f8aa6', fontSize: 17 }}>↗</Text>
                </View>
                <Text style={s.toolCat}>{CATEGORIES.find((c) => c.key === tool.category)?.label === 'Links & pages' ? 'URLs & web' : CATEGORIES.find((c) => c.key === tool.category)?.label}</Text>
                <Text style={s.toolTitle}>{tool.title}</Text>
                <Text style={s.toolText}>{tool.lead}</Text>
                <View style={{ flexDirection: 'row', justifyContent: 'space-between', marginTop: 6 }}>
                  <Text style={{ color: colors.soft, fontSize: 13.5, fontFamily: fonts.semibold }}>Start analysis</Text>
                  <Text style={{ color: colors.soft }}>→</Text>
                </View>
              </LinearGradient>
            </Pressable>
          </Appear>
        ))}
        {!tools.length ? <Text style={ui.muted}>No tools match your search. Try a different name or category.</Text> : null}
      </View>

      <View style={{ gap: 14, marginTop: 14 }}>
        <Eyebrow>Return to the evidence</Eyebrow>
        <Text style={ui.section}>Recent reports.</Text>
        <Lead>Your latest saved scans, up to 15 reports.</Lead>
        <Button kind="secondary" label="Refresh ↻" onPress={load} />
        <View style={{ flexDirection: 'row', gap: 8 }}>
          {[['Reports returned', counts.total], ['Reported threats', counts.threats], ['Needs review', counts.review]].map(([label, value]) => (
            <View key={label as string} style={s.stat}>
              <Text style={{ color: colors.muted, fontSize: 12, fontFamily: fonts.regular }}>{label}</Text>
              <Text style={{ color: colors.text, fontSize: 22, fontFamily: fonts.bold }}>{value ?? '—'}</Text>
            </View>
          ))}
        </View>
        <Lead>Latest saved reports. Open a report for its findings and coverage.</Lead>
        {(recent ?? []).slice(0, 6).map((r) => (
          <Pressable key={r.id} onPress={() => router.push({ pathname: '/scan/[id]', params: { id: String(r.id) } })}
            style={({ pressed }) => [s.row, pressed && { backgroundColor: '#142b40' }]}>
            <View style={{ flex: 1, gap: 4 }}>
              <Text numberOfLines={1} style={{ color: colors.text, fontSize: 14, fontFamily: fonts.medium }}>{r.url}</Text>
              <Text style={{ color: colors.faint, fontSize: 12, fontFamily: fonts.mono }}>{r.date}</Text>
            </View>
            <VerdictBadge verdict={r.verdict} />
          </Pressable>
        ))}
        {recent && !recent.length ? <Text style={ui.muted}>No saved reports yet. Analyze your first URL above.</Text> : null}
        <Button kind="link" label="Open your account history →" onPress={() => router.navigate('/history')} />
      </View>

      <View style={s.aside}>
        <Icon name="shield" size={22} color={colors.cyan} />
        <View style={{ flex: 1, gap: 6 }}>
          <Text style={{ color: colors.text, fontSize: 16, fontFamily: fonts.bold }}>Evidence first. Always.</Text>
          <Text style={{ color: colors.soft, fontSize: 14, lineHeight: 22, fontFamily: fonts.regular }}>
            A dataset match, a heuristic warning and an unavailable check mean different things. Open a report to understand the distinction.
          </Text>
        </View>
      </View>
    </Page>
  );
}

const s = StyleSheet.create({
  launch: { borderRadius: 20, borderWidth: 1, borderColor: 'rgba(120,213,255,.19)', backgroundColor: '#101c2c', overflow: 'hidden' },
  paste: { width: 38, height: 38, borderRadius: 9, alignItems: 'center', justifyContent: 'center', backgroundColor: 'rgba(119,220,255,.1)', borderWidth: 1, borderColor: 'rgba(119,220,255,.3)' },
  note: { flexDirection: 'row', gap: 10, paddingTop: 14, borderTopWidth: 1, borderTopColor: 'rgba(145,188,220,.12)' },
  filter: { paddingVertical: 8, paddingHorizontal: 14, borderRadius: 8, borderWidth: 1, borderColor: colors.line, backgroundColor: 'rgba(13,24,40,.7)' },
  tool: { padding: 23, borderRadius: 15, borderWidth: 1, borderColor: colors.line, gap: 6 },
  toolIcon: { width: 43, height: 43, borderRadius: 13, alignItems: 'center', justifyContent: 'center', borderWidth: 1, borderColor: 'rgba(114,223,255,.19)', backgroundColor: 'rgba(109,202,255,.04)' },
  toolCat: { color: '#7d9ab0', fontSize: 11.5, letterSpacing: 1, fontFamily: fonts.mono, marginTop: 14 },
  toolTitle: { color: colors.text, fontSize: 19, fontFamily: fonts.bold, letterSpacing: -0.4 },
  toolText: { color: colors.soft, fontSize: 14, lineHeight: 22, fontFamily: fonts.regular },
  stat: { flex: 1, padding: 12, borderRadius: 10, borderWidth: 1, borderColor: colors.line, backgroundColor: '#0f1a29', gap: 6 },
  row: { flexDirection: 'row', alignItems: 'center', gap: 10, padding: 12, borderRadius: 10, borderWidth: 1, borderColor: colors.line, backgroundColor: '#0f1a29' },
  aside: { flexDirection: 'row', gap: 14, padding: 20, borderRadius: 16, borderWidth: 1, borderColor: colors.line, backgroundColor: '#0d1726', marginTop: 10 },
});
