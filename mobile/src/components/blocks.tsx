import { LinearGradient } from 'expo-linear-gradient';
import { router } from 'expo-router';
import { StyleSheet, Text, View } from 'react-native';
import Animated from 'react-native-reanimated';

import { Icon } from '@/components/icon';
import { enter, PressableScale } from '@/components/motion';
import { openTool } from '@/components/screen';
import { VerdictBadge } from '@/components/ui';
import { ago, colors, fonts, tone, toneStyle } from '@/lib/theme';
import type { Tool } from '@/lib/tools';

export type Report = { id: number; url: string; verdict: string; date: string };

/** A section title with an optional action on the right. */
export function SectionHead({ title, action, onAction }: { title: string; action?: string; onAction?: () => void }) {
  return (
    <View style={{ flexDirection: 'row', alignItems: 'flex-end', marginTop: 8 }}>
      <Text style={s.section}>{title}</Text>
      {action ? (
        <PressableScale onPress={onAction} style={{ marginLeft: 'auto', paddingVertical: 4 }}>
          <Text style={{ color: colors.cyan, fontFamily: fonts.semibold, fontSize: 14 }}>{action}</Text>
        </PressableScale>
      ) : null}
    </View>
  );
}

/** Square tool tile for the home grid. */
export function ToolTile({ tool, index }: { tool: Tool; index: number }) {
  return (
    <Animated.View entering={enter(index)} style={{ width: '48%', flexGrow: 1 }}>
      <PressableScale onPress={() => openTool(tool)} accessibilityLabel={tool.title}>
        <LinearGradient colors={['#13202f', '#0d1522']} start={{ x: 0, y: 0 }} end={{ x: 1, y: 1 }} style={s.tile}>
          <View style={s.tileIcon}><Icon name={tool.icon} size={20} color={colors.cyan} /></View>
          <Text style={s.tileTitle} numberOfLines={1}>{tool.title}</Text>
          <Text style={s.tileText} numberOfLines={2}>{tool.menu}</Text>
        </LinearGradient>
      </PressableScale>
    </Animated.View>
  );
}

/** One saved report in a list, with a colour rail for its verdict. */
export function ReportRow({ report, index }: { report: Report; index: number }) {
  const t = toneStyle[tone(report.verdict)];
  let host = report.url;
  try { host = new URL(report.url).host || report.url; } catch {}
  return (
    <Animated.View entering={enter(index)}>
      <PressableScale scale={0.98} onPress={() => router.push({ pathname: '/scan/[id]', params: { id: String(report.id) } })} style={s.row}>
        <View style={[s.rail, { backgroundColor: t.color }]} />
        <View style={[s.rowIcon, { backgroundColor: t.color + '14', borderColor: t.color + '44' }]}>
          <Icon name={tone(report.verdict) === 'safe' ? 'check' : tone(report.verdict) === 'unknown' ? 'link' : 'alert'} size={17} color={t.color} />
        </View>
        <View style={{ flex: 1, gap: 5 }}>
          <Text numberOfLines={1} style={{ color: colors.text, fontSize: 15, fontFamily: fonts.semibold }}>{host}</Text>
          <Text numberOfLines={1} style={{ color: colors.faint, fontSize: 12.5, fontFamily: fonts.regular }}>{report.url}</Text>
        </View>
        <View style={{ alignItems: 'flex-end', gap: 6 }}>
          <VerdictBadge verdict={report.verdict} />
          <Text style={{ color: colors.faint, fontSize: 11.5, fontFamily: fonts.mono }}>{ago(report.date)}</Text>
        </View>
      </PressableScale>
    </Animated.View>
  );
}

/** Empty state with an icon and a short line. */
export function Empty({ icon, title, text }: { icon: 'clock' | 'search' | 'link'; title: string; text: string }) {
  return (
    <Animated.View entering={enter(1)} style={{ alignItems: 'center', gap: 8, paddingVertical: 30 }}>
      <View style={[s.rowIcon, { width: 56, height: 56, borderRadius: 18, backgroundColor: 'rgba(119,220,255,.06)', borderColor: 'rgba(119,220,255,.2)' }]}>
        <Icon name={icon} size={24} color={colors.cyan} />
      </View>
      <Text style={{ color: colors.text, fontSize: 17, fontFamily: fonts.bold }}>{title}</Text>
      <Text style={{ color: colors.muted, fontSize: 14, textAlign: 'center', lineHeight: 21, fontFamily: fonts.regular, maxWidth: 280 }}>{text}</Text>
    </Animated.View>
  );
}

const s = StyleSheet.create({
  section: { color: colors.text, fontSize: 21, fontFamily: fonts.bold, letterSpacing: -0.5 },
  tile: { padding: 16, borderRadius: 20, borderWidth: 1, borderColor: colors.line, gap: 6, minHeight: 138 },
  tileIcon: { width: 42, height: 42, borderRadius: 13, alignItems: 'center', justifyContent: 'center', borderWidth: 1,
    borderColor: 'rgba(119,220,255,.22)', backgroundColor: 'rgba(119,220,255,.07)', marginBottom: 6 },
  tileTitle: { color: colors.text, fontSize: 15.5, fontFamily: fonts.bold },
  tileText: { color: colors.muted, fontSize: 12.5, lineHeight: 18, fontFamily: fonts.regular },
  row: { flexDirection: 'row', alignItems: 'center', gap: 12, padding: 14, paddingLeft: 16, borderRadius: 18, borderWidth: 1,
    borderColor: colors.line, backgroundColor: '#0e1825', overflow: 'hidden' },
  rail: { position: 'absolute', left: 0, top: 14, bottom: 14, width: 3, borderRadius: 3 },
  rowIcon: { width: 38, height: 38, borderRadius: 12, alignItems: 'center', justifyContent: 'center', borderWidth: 1 },
});
