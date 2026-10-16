import { Text, View } from 'react-native';

import { colors } from '@/lib/theme';

// Internal or technical fields that only add noise to a quick read; the AI explanation covers them.
const SKIP = /html|screenshot|image|base64|raw|privacy|polic|schema|token|estimator|deduction|guesses|scope|weight|version|^final$|coverage|status_url|task|^id$/i;

const humanize = (key: string) => key.replace(/_/g, ' ').replace(/\b(ip|dns|tls|ssl|mx|spf|dkim|dmarc|url|ct|asn)\b/gi, (m) => m.toUpperCase());

function short(value: unknown): string | null {
  if (value === null || value === undefined || value === '') return null;
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (typeof value === 'number') return String(value);
  if (typeof value === 'string') return value.length > 160 ? `${value.slice(0, 160)}…` : value.replace(/_/g, ' ');
  if (Array.isArray(value)) {
    const simple = value.filter((v) => ['string', 'number'].includes(typeof v));
    if (!simple.length) return null;
    return simple.slice(0, 6).join(', ') + (value.length > 6 ? ` (+${value.length - 6})` : '');
  }
  return null;
}

/** Plain facts from a result object, for a quick read before the AI explanation. */
export function Details({ data, limit = 12 }: { data: Record<string, unknown>; limit?: number }) {
  const rows: [string, string][] = [];
  const advice: string[] = Array.isArray((data as any)?.recommendations)
    ? (data as any).recommendations.filter((r: unknown) => typeof r === 'string').slice(0, 4) : [];
  const visit = (obj: Record<string, unknown>, prefix = '') => {
    for (const [key, value] of Object.entries(obj)) {
      if (rows.length >= limit || SKIP.test(key) || key === 'recommendations') continue;
      const text = short(value);
      if (text !== null) rows.push([humanize(prefix ? `${prefix} · ${key}` : key), text]);
      else if (value && typeof value === 'object' && !Array.isArray(value) && !prefix) visit(value as Record<string, unknown>, key);
    }
  };
  visit(data);
  return (
    <View style={{ gap: 10 }}>
      {rows.map(([k, v]) => (
        <View key={k} style={{ flexDirection: 'row', gap: 12 }}>
          <Text style={{ width: '42%', color: colors.faint, fontSize: 13, textTransform: 'capitalize' }}>{k}</Text>
          <Text selectable style={{ flex: 1, color: colors.text, fontSize: 14.5 }}>{v}</Text>
        </View>
      ))}
      {advice.length ? (
        <View style={{ gap: 6, marginTop: 4 }}>
          <Text style={{ color: colors.green, fontSize: 12, fontWeight: '800', letterSpacing: 1 }}>WHAT TO DO</Text>
          {advice.map((a) => <Text key={a} style={{ color: colors.soft, fontSize: 14.5, lineHeight: 21 }}>{'•  '}{a}</Text>)}
        </View>
      ) : null}
    </View>
  );
}
