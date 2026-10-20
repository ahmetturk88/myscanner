import { useFocusEffect } from 'expo-router';
import { useCallback, useEffect, useState } from 'react';
import { Pressable, StyleSheet, Text, TextInput, View } from 'react-native';
import Animated, { useAnimatedStyle, useSharedValue, withSpring } from 'react-native-reanimated';

import { Empty, ReportRow, type Report } from '@/components/blocks';
import { Icon } from '@/components/icon';
import { Screen } from '@/components/screen';
import { ErrorText, Skeleton, styles as ui } from '@/components/ui';
import { api } from '@/lib/api';
import { t } from '@/lib/i18n';
import { colors, fonts, tone, type Tone } from '@/lib/theme';

const filters = (): { key: 'all' | Tone; label: string }[] => [
  { key: 'all', label: t('All') }, { key: 'risk', label: t('Threats') }, { key: 'review', label: t('Review') }, { key: 'safe', label: t('Clean') },
];

/** Segmented control whose highlight slides to the chosen option. */
function Segments({ value, onChange }: { value: string; onChange: (key: 'all' | Tone) => void }) {
  const [width, setWidth] = useState(0);
  const [FILTERS] = useState(filters);
  const x = useSharedValue(0);
  const index = FILTERS.findIndex((f) => f.key === value);
  useEffect(() => { x.value = withSpring(index * (width / FILTERS.length), { damping: 18, stiffness: 220 }); }, [index, width, x, FILTERS.length]);
  const pill = useAnimatedStyle(() => ({ transform: [{ translateX: x.value }] }));
  return (
    <View style={s.segments} onLayout={(e) => setWidth(e.nativeEvent.layout.width - 8)}>
      {width ? <Animated.View style={[s.segPill, { width: width / FILTERS.length }, pill]} /> : null}
      {FILTERS.map((f) => (
        <Pressable key={f.key} accessibilityRole="tab" accessibilityState={{ selected: f.key === value }} onPress={() => onChange(f.key)} style={s.seg}>
          <Text style={{ color: f.key === value ? colors.text : colors.muted, fontSize: 13.5, fontFamily: fonts.semibold }}>{f.label}</Text>
        </Pressable>
      ))}
    </View>
  );
}

export default function History() {
  const [rows, setRows] = useState<Report[] | null>(null);
  const [filter, setFilter] = useState<'all' | Tone>('all');
  const [query, setQuery] = useState('');
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try { const data = await api.recent(); setRows(data.scans); setError(null); } catch (e: any) { setError(e.message); }
  }, []);
  useFocusEffect(useCallback(() => { load(); }, [load]));
  const q = query.trim().toLowerCase();
  const shown = (rows ?? []).filter((r) => (filter === 'all' || tone(r.verdict) === filter) && (!q || r.url.toLowerCase().includes(q)));

  return (
    <Screen tabs eyebrow={t('Your evidence')} title={t('History')} subtitle={t('Every link you scanned, newest first.')} onRefresh={load} gap={14}>
      <View style={ui.inputWrap}>
        <Icon name="search" size={17} color={colors.faint} />
        <TextInput value={query} onChangeText={setQuery} placeholder={t('Search your reports')} placeholderTextColor="#5f7590" style={ui.input}
          autoCapitalize="none" autoCorrect={false} />
      </View>
      <Segments value={filter} onChange={setFilter} />
      <ErrorText>{error}</ErrorText>
      {!rows && !error ? <View style={{ gap: 10 }}>{[0, 1, 2, 3].map((i) => <Skeleton key={i} height={70} />)}</View> : null}
      <View style={{ gap: 10 }}>
        {shown.map((r, i) => <ReportRow key={`${filter}-${r.id}`} report={r} index={i} />)}
      </View>
      {rows && !shown.length ? (
        <Empty icon={q ? 'search' : 'clock'} title={rows.length ? t('Nothing matches') : t('No reports yet')}
          text={rows.length ? t('Try another filter or search.') : t('Scan a link from Home and its report will appear here.')} />
      ) : null}
    </Screen>
  );
}

const s = StyleSheet.create({
  segments: { flexDirection: 'row', padding: 4, borderRadius: 14, backgroundColor: '#0c1522', borderWidth: 1, borderColor: colors.line },
  segPill: { position: 'absolute', top: 4, bottom: 4, left: 4, borderRadius: 10, backgroundColor: '#17324a', borderWidth: 1, borderColor: 'rgba(119,220,255,.3)' },
  seg: { flex: 1, alignItems: 'center', paddingVertical: 9 },
});
