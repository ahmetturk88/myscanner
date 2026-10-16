import { router, useFocusEffect } from 'expo-router';
import { useCallback, useState } from 'react';
import { FlatList, Pressable, RefreshControl, Text, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

import { TAB_BAR_SPACE } from '@/components/app-tabs';
import { Icon } from '@/components/icon';
import { Backdrop, ErrorText, Muted, Skeleton, Title } from '@/components/ui';
import { api } from '@/lib/api';
import { ago, colors, tone, toneStyle, type Tone } from '@/lib/theme';

type Row = { id: number; url: string; verdict: string; date: string };
const FILTERS: { key: 'all' | Tone; label: string }[] = [
  { key: 'all', label: 'All' }, { key: 'risk', label: 'High risk' }, { key: 'review', label: 'Review' }, { key: 'safe', label: 'Clear' },
];

export default function History() {
  const [rows, setRows] = useState<Row[] | null>(null);
  const [filter, setFilter] = useState<'all' | Tone>('all');
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async () => {
    try {
      const data = await api.recent();
      setRows(data.scans); setError(null);
    } catch (e: any) { setError(e.message); }
  }, []);

  useFocusEffect(useCallback(() => { load(); }, [load]));
  const shown = (rows ?? []).filter((r) => filter === 'all' || tone(r.verdict) === filter);

  return (
    <Backdrop>
      <SafeAreaView style={{ flex: 1 }} edges={['top']}>
        <FlatList
          data={shown}
          keyExtractor={(row) => String(row.id)}
          contentContainerStyle={{ padding: 16, paddingBottom: TAB_BAR_SPACE, gap: 10 }}
          showsVerticalScrollIndicator={false}
          refreshControl={<RefreshControl refreshing={refreshing} tintColor={colors.cyan} colors={[colors.cyan]}
            onRefresh={async () => { setRefreshing(true); await load(); setRefreshing(false); }} />}
          ListHeaderComponent={
            <View style={{ gap: 12, marginBottom: 4 }}>
              <Title kicker="HISTORY" sub="Your latest link reports. Pull down to refresh.">Recent reports</Title>
              <View style={{ flexDirection: 'row', gap: 8 }}>
                {FILTERS.map((f) => {
                  const on = filter === f.key;
                  return (
                    <Pressable key={f.key} accessibilityRole="button" accessibilityState={{ selected: on }} onPress={() => setFilter(f.key)}
                      style={{ paddingVertical: 8, paddingHorizontal: 13, borderRadius: 999, borderWidth: 1,
                        borderColor: on ? colors.cyan : colors.line, backgroundColor: on ? colors.cyan + '22' : colors.surface }}>
                      <Text style={{ color: on ? colors.cyanSoft : colors.muted, fontWeight: '700', fontSize: 13 }}>{f.label}</Text>
                    </Pressable>
                  );
                })}
              </View>
              <ErrorText>{error}</ErrorText>
              {!rows && !error ? <View style={{ gap: 10 }}><Skeleton /><Skeleton /><Skeleton /></View> : null}
            </View>
          }
          ListEmptyComponent={rows ? <Muted>{filter === 'all' ? 'No scans yet. Check your first link from Home.' : 'Nothing here.'}</Muted> : undefined}
          renderItem={({ item }) => {
            const t = toneStyle[tone(item.verdict)];
            return (
              <Pressable accessibilityRole="button" onPress={() => router.push({ pathname: '/scan/[id]', params: { id: String(item.id) } })}
                style={({ pressed }) => ({ flexDirection: 'row', overflow: 'hidden', borderRadius: 18, borderWidth: 1, borderColor: colors.line,
                  backgroundColor: pressed ? colors.surface2 : colors.surface })}>
                <View style={{ width: 4, backgroundColor: t.color }} />
                <View style={{ flex: 1, padding: 14, gap: 8 }}>
                  <Text numberOfLines={2} style={{ color: colors.text, fontSize: 15, fontWeight: '700' }}>{item.url}</Text>
                  <View style={{ flexDirection: 'row', alignItems: 'center', gap: 8 }}>
                    <View style={{ width: 8, height: 8, borderRadius: 4, backgroundColor: t.color }} />
                    <Text style={{ color: t.color, fontWeight: '700', fontSize: 13 }}>{t.label}</Text>
                    <Text style={{ color: colors.faint, fontSize: 12, marginLeft: 'auto' }}>{ago(item.date)}</Text>
                  </View>
                </View>
                <View style={{ justifyContent: 'center', paddingRight: 12 }}><Icon name="chevron" size={18} color={colors.faint} /></View>
              </Pressable>
            );
          }}
        />
      </SafeAreaView>
    </Backdrop>
  );
}
