import { router, useFocusEffect } from 'expo-router';
import { useCallback, useState } from 'react';
import { FlatList, Pressable, RefreshControl, Text, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

import { ErrorText, Muted, Title, VerdictBadge } from '@/components/ui';
import { api } from '@/lib/api';
import { colors, radius } from '@/lib/theme';

type Row = { id: number; url: string; verdict: string; date: string };

export default function History() {
  const [rows, setRows] = useState<Row[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async () => {
    try {
      const data = await api.recent();
      setRows(data.scans); setError(null);
    } catch (e: any) { setError(e.message); }
  }, []);

  useFocusEffect(useCallback(() => { load(); }, [load]));

  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: colors.bg }} edges={['top']}>
      <FlatList
        data={rows ?? []}
        keyExtractor={(row) => String(row.id)}
        contentContainerStyle={{ padding: 16, paddingBottom: 40, gap: 10 }}
        refreshControl={<RefreshControl refreshing={refreshing} tintColor={colors.cyan}
          onRefresh={async () => { setRefreshing(true); await load(); setRefreshing(false); }} />}
        ListHeaderComponent={<View><Title kicker="HISTORY" sub="Your latest link scans. Pull down to refresh.">Recent reports</Title><ErrorText>{error}</ErrorText></View>}
        ListEmptyComponent={rows ? <Muted>No scans yet. Check your first link from the Scan tab.</Muted> : undefined}
        renderItem={({ item }) => (
          <Pressable accessibilityRole="button" onPress={() => router.push({ pathname: '/scan/[id]', params: { id: String(item.id) } })}
            style={({ pressed }) => ({ backgroundColor: pressed ? colors.surface2 : colors.surface, borderRadius: radius.md,
              borderWidth: 1, borderColor: colors.line, padding: 14, gap: 8 })}>
            <Text numberOfLines={2} style={{ color: colors.text, fontSize: 15, fontWeight: '600' }}>{item.url}</Text>
            <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' }}>
              <VerdictBadge verdict={item.verdict} />
              <Text style={{ color: colors.faint, fontSize: 12 }}>{item.date}</Text>
            </View>
          </Pressable>
        )}
      />
    </SafeAreaView>
  );
}
