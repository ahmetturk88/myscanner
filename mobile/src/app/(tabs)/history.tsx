import { router, useFocusEffect } from 'expo-router';
import { useCallback, useState } from 'react';
import { Pressable, Text, View } from 'react-native';

import { Page } from '@/components/site';
import { Button, ErrorText, Eyebrow, Hero, Lead, Skeleton, styles as ui, VerdictBadge } from '@/components/ui';
import { api } from '@/lib/api';
import { ago, colors, fonts, tone, type Tone } from '@/lib/theme';

type Row = { id: number; url: string; verdict: string; date: string };
const FILTERS: { key: 'all' | Tone; label: string }[] = [
  { key: 'all', label: 'All' }, { key: 'risk', label: 'Threats' }, { key: 'review', label: 'Needs review' }, { key: 'safe', label: 'No indicators' },
];

export default function History() {
  const [rows, setRows] = useState<Row[] | null>(null);
  const [filter, setFilter] = useState<'all' | Tone>('all');
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const data = await api.recent();
      setRows(data.scans); setError(null);
    } catch (e: any) { setError(e.message); }
  }, []);
  useFocusEffect(useCallback(() => { load(); }, [load]));
  const shown = (rows ?? []).filter((r) => filter === 'all' || tone(r.verdict) === filter);

  return (
    <Page>
      <View style={{ gap: 14 }}>
        <Eyebrow>Return to the evidence</Eyebrow>
        <Hero title="Recent reports." size={34} />
        <Lead>Your latest saved URL scans. Open a report for its findings and coverage.</Lead>
        <Button kind="secondary" label="Refresh ↻" onPress={load} />
      </View>
      <View style={{ flexDirection: 'row', flexWrap: 'wrap', gap: 8 }}>
        {FILTERS.map((f) => {
          const on = filter === f.key;
          return (
            <Pressable key={f.key} onPress={() => setFilter(f.key)} accessibilityState={{ selected: on }}
              style={{ paddingVertical: 8, paddingHorizontal: 14, borderRadius: 8, borderWidth: 1,
                borderColor: on ? '#2b7289' : colors.line, backgroundColor: on ? '#123a52' : 'rgba(13,24,40,.7)' }}>
              <Text style={{ color: on ? '#e6f7ff' : '#a9bbd2', fontSize: 13, fontFamily: fonts.medium }}>{f.label}</Text>
            </Pressable>
          );
        })}
      </View>
      <ErrorText>{error}</ErrorText>
      {!rows && !error ? <View style={{ gap: 10 }}><Skeleton /><Skeleton /><Skeleton /></View> : null}
      <View style={{ gap: 10 }}>
        {shown.map((r) => (
          <Pressable key={r.id} onPress={() => router.push({ pathname: '/scan/[id]', params: { id: String(r.id) } })}
            style={({ pressed }) => ({ gap: 8, padding: 14, borderRadius: 12, borderWidth: 1, borderColor: colors.line,
              backgroundColor: pressed ? '#142b40' : '#0f1a29' })}>
            <Text numberOfLines={2} style={{ color: colors.text, fontSize: 14.5, fontFamily: fonts.medium }}>{r.url}</Text>
            <View style={{ flexDirection: 'row', alignItems: 'center' }}>
              <VerdictBadge verdict={r.verdict} />
              <Text style={{ marginLeft: 'auto', color: colors.faint, fontSize: 12, fontFamily: fonts.mono }}>{ago(r.date)}</Text>
            </View>
          </Pressable>
        ))}
        {rows && !shown.length ? <Text style={ui.muted}>{filter === 'all' ? 'No saved reports yet.' : 'Nothing here.'}</Text> : null}
      </View>
    </Page>
  );
}
