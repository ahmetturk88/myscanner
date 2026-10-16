import { Text, View } from 'react-native';

import { colors } from '@/lib/theme';

const SKIP = /html|screenshot|image|base64|raw|privacy|policy_version|schema|token/i;

function short(value: unknown): string | null {
  if (value === null || value === undefined || value === '') return null;
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (typeof value === 'number') return String(value);
  if (typeof value === 'string') return value.length > 160 ? `${value.slice(0, 160)}…` : value;
  if (Array.isArray(value)) {
    const simple = value.filter((v) => ['string', 'number'].includes(typeof v));
    return simple.length ? simple.slice(0, 6).join(', ') + (value.length > 6 ? ` (+${value.length - 6})` : '') : `${value.length} items`;
  }
  return null;
}

/** The first plain facts of a result object, for a quick read before the AI explanation. */
export function Details({ data, limit = 14 }: { data: Record<string, unknown>; limit?: number }) {
  const rows: [string, string][] = [];
  const visit = (obj: Record<string, unknown>, prefix = '') => {
    for (const [key, value] of Object.entries(obj)) {
      if (rows.length >= limit || SKIP.test(key)) continue;
      const text = short(value);
      if (text !== null) rows.push([`${prefix}${key}`.replace(/_/g, ' '), text]);
      else if (value && typeof value === 'object' && !Array.isArray(value) && !prefix) visit(value as Record<string, unknown>, `${key} · `);
    }
  };
  visit(data);
  if (!rows.length) return null;
  return (
    <View style={{ gap: 8 }}>
      {rows.map(([k, v]) => (
        <View key={k} style={{ gap: 2 }}>
          <Text style={{ color: colors.faint, fontSize: 12, textTransform: 'capitalize' }}>{k}</Text>
          <Text selectable style={{ color: colors.text, fontSize: 15 }}>{v}</Text>
        </View>
      ))}
    </View>
  );
}
