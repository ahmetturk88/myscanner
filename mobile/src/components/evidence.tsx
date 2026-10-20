import * as Clipboard from 'expo-clipboard';
import * as Haptics from '@/lib/haptics';
import { useEffect, useState } from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';
import Animated, { FadeIn, LinearTransition, useAnimatedStyle, useSharedValue, withTiming } from 'react-native-reanimated';

import { Icon } from '@/components/icon';
import { enter, PressableScale } from '@/components/motion';
import { getSettings } from '@/lib/settings';
import { colors, fonts } from '@/lib/theme';

// Page markup, images and internal bookkeeping: noise in a phone report, and sometimes megabytes.
const HIDDEN = /(^|_)(html|base64|screenshot|image|status_url|task_id|csrf)($|_)|^plain$|^result_html$|^schema_version$/i;
const PAGE = 20;
const LONG = 280;

const NAMES = /\b(ip|ipv4|ipv6|dns|tls|ssl|mx|spf|dkim|dmarc|url|urls|ct|asn|http|https|tcp|rdap|whois|sha256|sha1|md5|id|ttl|cname|aaaa|txt|ns|soa|caa|ptr|osint|api|uri|cn|san|ocsp)\b/gi;
export const humanize = (key: string) => {
  const words = key.replace(/([a-z])([A-Z])/g, '$1 $2').replace(/[_-]+/g, ' ').trim();
  return (words.charAt(0).toUpperCase() + words.slice(1)).replace(NAMES, (m) => m.toUpperCase());
};

type Node = unknown;
const isObject = (v: Node): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const empty = (v: Node) => v === null || v === undefined || v === '' || (Array.isArray(v) && !v.length) || (isObject(v) && !Object.keys(v).length);

/** Entries worth showing: no hidden keys, no blank values. */
function entries(value: Record<string, unknown>) {
  return Object.entries(value).filter(([k, v]) => !HIDDEN.test(k) && !empty(v));
}

/** A friendly title for one item of a list (a hostname, a record type, a source name). */
function itemTitle(item: Node, index: number) {
  if (isObject(item)) {
    for (const key of ['hostname', 'host', 'subdomain', 'name', 'domain', 'source', 'engine', 'provider', 'type', 'title', 'url', 'action', 'code', 'check', 'value']) {
      const v = item[key];
      if (typeof v === 'string' && v.trim()) return v.length > 60 ? `${v.slice(0, 60)}…` : v;
    }
  }
  return `Item ${index + 1}`;
}

function count(value: Node) {
  if (Array.isArray(value)) return `${value.length} item${value.length === 1 ? '' : 's'}`;
  if (isObject(value)) { const n = entries(value).length; return `${n} field${n === 1 ? '' : 's'}`; }
  return '';
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
// Emoji and symbols some analyzers put in front of their notes (🛡️, 🚩, ✅).
const EMOJI = /^(?:[\u2190-\u21FF\u2300-\u27BF\u2B00-\u2BFF]|\uD83C[\uDC00-\uDFFF]|\uD83D[\uDC00-\uDFFF]|\uD83E[\uDD00-\uDFFF]|\uFE0F|\u200D|\s)+/;

function span(days: number) {
  return days < 60 ? `${days} day${days === 1 ? '' : 's'}` : days < 730 ? `${Math.floor(days / 30)} months` : `${Math.floor(days / 365)} years`;
}

/** A value as a person would write it: dates, day counts and status words made readable. */
export function readable(value: Node, key = ''): string {
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (typeof value === 'number') {
    if (/(^|_)days?($|_)|^domain_age$/i.test(key) && Number.isInteger(value)) {
      return value < 0 ? (/until|remaining|left/i.test(key) ? `Passed ${span(-value)} ago` : `${span(-value)} ago`) : value >= 60 ? `${value.toLocaleString('en-US')} days (${span(value)})` : span(value);
    }
    return value.toLocaleString('en-US', { maximumFractionDigits: 2 });
  }
  let text = String(value).replace(EMOJI, '');
  const date = text.match(/^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})[^Z+-]*(Z|[+-]\d{2}:?\d{2})?)?$/);
  if (date) {
    const [, y, m, d, hh, mm] = date;
    return `${Number(d)} ${MONTHS[Number(m) - 1] ?? m} ${y}` + (hh ? `, ${hh}:${mm} UTC` : '');
  }
  if (/^[A-Z0-9-]+(\.[A-Z0-9-]+)+\.?$/.test(text) && /[A-Z]/.test(text)) return text.toLowerCase();  // HOST.NAME.COM
  if (/^[a-z]+(_[a-z]+)+$/.test(text) || /^[a-z]{3,20}$/.test(text) || /^[A-Z]{6,}(_[A-Z]+)*$/.test(text)) {
    text = text.replace(/_/g, ' ').toLowerCase();  // status words: high_risk, partial, UNKNOWN
    return text.charAt(0).toUpperCase() + text.slice(1);
  }
  return text;
}

function Value({ value, field = '' }: { value: Node; field?: string }) {
  const [all, setAll] = useState(false);
  if (value === null || value === undefined) return <Text style={[st.value, { color: colors.faint }]}>—</Text>;
  if (Array.isArray(value)) {
    // A short list reads best one item per line, not joined with commas.
    return <View style={{ gap: 4 }}>{value.map((v, i) => <Value key={i} value={v} field={field} />)}</View>;
  }
  // Yes/No stays neutral: whether "Yes" is good depends on the question.
  const text = readable(value, field);
  // Long unbroken strings (keys, hashes, encoded data) read better in the mono font.
  const mono = /^[A-Za-z0-9+/=_-]{24,}$/.test(text);
  const long = text.length > LONG;
  return (
    <Text selectable style={[st.value, mono && { fontFamily: fonts.mono, fontSize: 12.5 }]}>
      {long && !all ? `${text.slice(0, LONG)}… ` : text}
      {long ? <Text onPress={() => setAll(!all)} style={{ color: colors.cyan, fontFamily: fonts.semibold }}>{all ? '  Show less' : 'Show all'}</Text> : null}
    </Text>
  );
}

/** Opens and closes with a turning chevron; children render only while open. */
function Group({ title, meta, depth, children, initiallyOpen = false }: { title: string; meta?: string; depth: number; children: () => React.ReactNode; initiallyOpen?: boolean }) {
  const [open, setOpen] = useState(initiallyOpen);
  const turn = useSharedValue(initiallyOpen ? 1 : 0);
  useEffect(() => { turn.value = withTiming(open ? 1 : 0, { duration: 220 }); }, [open, turn]);
  const chevron = useAnimatedStyle(() => ({ transform: [{ rotate: `${turn.value * 90}deg` }] }));
  return (
    <Animated.View layout={LinearTransition.duration(220)} style={[depth > 0 && st.nested]}>
      <Pressable accessibilityRole="button" accessibilityState={{ expanded: open }} onPress={() => { Haptics.selectionAsync().catch(() => {}); setOpen(!open); }}
        style={({ pressed }) => [st.groupHead, pressed && { opacity: 0.7 }]}>
        <Animated.View style={chevron}><Icon name="chevron" size={15} color={open ? colors.cyan : colors.faint} stroke={2.4} /></Animated.View>
        <Text style={[st.groupTitle, depth === 0 && { fontSize: 15.5, color: colors.text }]} numberOfLines={2}>{title}</Text>
        {meta ? <Text style={st.meta}>{meta}</Text> : null}
      </Pressable>
      {open ? <Animated.View entering={FadeIn.duration(260)} style={{ gap: 2, paddingLeft: 6 }}>{children()}</Animated.View> : null}
    </Animated.View>
  );
}

/** A long list shows its first page, then more on request. */
function Paged<T>({ items, render }: { items: T[]; render: (item: T, index: number) => React.ReactNode }) {
  const [shown, setShown] = useState(PAGE);
  return (
    <>
      {items.slice(0, shown).map(render)}
      {items.length > shown ? (
        <Pressable onPress={() => setShown(shown + PAGE * 2)} style={st.more}>
          <Text style={{ color: colors.cyan, fontSize: 13.5, fontFamily: fonts.semibold }}>{`Show ${Math.min(items.length - shown, PAGE * 2)} more`}</Text>
        </Pressable>
      ) : null}
    </>
  );
}

/** Objects and long lists open as groups; short lists of plain values stay inline. */
const nested = (v: Node) => isObject(v) || (Array.isArray(v) && !(v.every((x) => !isObject(x) && !Array.isArray(x)) && v.length <= 4));

/** Plain values first, then the groups, so a value never looks like part of the group above it. */
function ordered(items: [string, unknown][]) {
  return [...items.filter(([, v]) => !nested(v)), ...items.filter(([, v]) => nested(v))];
}

function Tree({ value, depth }: { value: Node; depth: number }) {
  if (Array.isArray(value)) {
    const items = value.filter((v) => !empty(v));
    if (items.every((v) => !isObject(v) && !Array.isArray(v))) {
      return (
        <View style={st.chips}>
          <Paged items={items} render={(v, i) => <View key={i} style={st.chip}><Text selectable style={st.chipText}>{readable(v)}</Text></View>} />
        </View>
      );
    }
    return (
      <Paged items={items} render={(item, i) => (isObject(item) || Array.isArray(item)
        ? <Group key={i} title={itemTitle(item, i)} meta={count(item)} depth={depth + 1}>{() => <Tree value={item} depth={depth + 1} />}</Group>
        : <Row key={i} name={`Item ${i + 1}`} value={item} />)} />
    );
  }
  if (isObject(value)) {
    return (
      <Paged items={ordered(entries(value))} render={([key, v]) => nested(v)
        ? <Group key={key} title={humanize(key)} meta={count(v)} depth={depth + 1}>{() => <Tree value={v} depth={depth + 1} />}</Group>
        : <Row key={key} name={humanize(key)} field={key} value={v} />} />
    );
  }
  return <Value value={value} />;
}

function Row({ name, value, field }: { name: string; value: Node; field?: string }) {
  return (
    <View style={st.row}>
      <Text style={st.key}>{name}</Text>
      <View style={{ flex: 1 }}><Value value={value} field={field} /></View>
    </View>
  );
}

/** Everything the check collected, browsable in the app. Closed until asked for. */
export function Evidence({ data, start = 0, title = 'Full technical evidence' }: { data: Record<string, unknown> | null | undefined; start?: number; title?: string }) {
  const [open, setOpen] = useState(() => getSettings().evidenceOpen);
  const [copied, setCopied] = useState(false);
  const turn = useSharedValue(open ? 1 : 0);
  useEffect(() => { turn.value = withTiming(open ? 1 : 0, { duration: 260 }); }, [open, turn]);
  const chevron = useAnimatedStyle(() => ({ transform: [{ rotate: `${90 + turn.value * 180}deg` }] }));
  if (!isObject(data)) return null;
  const sections = entries(data);
  if (!sections.length) return null;

  async function copy() {
    const clean = JSON.stringify(data, (k, v) => (k && HIDDEN.test(k) ? undefined : v), 2);
    await Clipboard.setStringAsync(clean).catch(() => {});
    Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 2200);
  }

  return (
    <Animated.View entering={enter(start)} layout={LinearTransition.duration(260)} style={st.card}>
      <PressableScale scale={0.99} accessibilityLabel={open ? 'Hide the technical evidence' : 'Show the technical evidence'} onPress={() => setOpen(!open)} style={st.head}>
        <View style={st.badge}><Icon name="code" size={19} color={colors.cyan} /></View>
        <View style={{ flex: 1, gap: 2 }}>
          <Text style={{ color: colors.text, fontSize: 17, fontFamily: fonts.bold }}>{title}</Text>
          <Text style={{ color: colors.faint, fontSize: 12.5, fontFamily: fonts.regular }}>{`${sections.length} sections · raw findings`}</Text>
        </View>
        <Animated.View style={chevron}><Icon name="chevron" size={18} color={colors.soft} stroke={2.4} /></Animated.View>
      </PressableScale>
      {open ? (
        <Animated.View entering={FadeIn.duration(300)} style={{ gap: 4 }}>
          <Pressable onPress={copy} style={({ pressed }) => [st.copy, pressed && { opacity: 0.7 }]}>
            <Icon name={copied ? 'check' : 'copy'} size={15} color={copied ? colors.green : colors.cyan} />
            <Text style={{ color: copied ? colors.green : colors.cyan, fontSize: 13, fontFamily: fonts.semibold }}>{copied ? 'Copied as JSON' : 'Copy all as JSON'}</Text>
          </Pressable>
          <Tree value={data} depth={-1} />
        </Animated.View>
      ) : null}
    </Animated.View>
  );
}

const st = StyleSheet.create({
  card: { gap: 12, padding: 16, borderRadius: 22, borderWidth: 1, borderColor: colors.line, backgroundColor: 'rgba(10,18,29,.94)', overflow: 'hidden' },
  head: { flexDirection: 'row', alignItems: 'center', gap: 12 },
  badge: { width: 40, height: 40, borderRadius: 13, alignItems: 'center', justifyContent: 'center', backgroundColor: 'rgba(119,220,255,.08)', borderWidth: 1, borderColor: 'rgba(119,220,255,.3)' },
  copy: { alignSelf: 'flex-start', flexDirection: 'row', alignItems: 'center', gap: 7, paddingVertical: 7, paddingHorizontal: 11, marginBottom: 6, borderRadius: 999, borderWidth: 1, borderColor: 'rgba(119,220,255,.3)', backgroundColor: 'rgba(119,220,255,.06)' },
  nested: { borderLeftWidth: 1, borderLeftColor: 'rgba(145,188,220,.16)', marginLeft: 6, paddingLeft: 8 },
  groupHead: { flexDirection: 'row', alignItems: 'center', gap: 8, paddingVertical: 10 },
  groupTitle: { flex: 1, color: colors.soft, fontSize: 14.5, fontFamily: fonts.semibold },
  meta: { color: colors.faint, fontSize: 11.5, fontFamily: fonts.mono },
  row: { flexDirection: 'row', gap: 12, paddingVertical: 8, borderBottomWidth: 1, borderBottomColor: 'rgba(145,188,220,.08)' },
  key: { width: '40%', color: colors.faint, fontSize: 13, lineHeight: 20, fontFamily: fonts.regular },
  value: { color: colors.text, fontSize: 14, lineHeight: 20, fontFamily: fonts.medium },
  chips: { flexDirection: 'row', flexWrap: 'wrap', gap: 6, paddingVertical: 6 },
  chip: { paddingVertical: 5, paddingHorizontal: 10, borderRadius: 8, backgroundColor: 'rgba(19,36,58,.9)', borderWidth: 1, borderColor: colors.line },
  chipText: { color: colors.soft, fontSize: 12.5, fontFamily: fonts.mono },
  more: { alignSelf: 'flex-start', paddingVertical: 9, paddingHorizontal: 4 },
});
