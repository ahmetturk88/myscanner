import * as Haptics from 'expo-haptics';
import { useLocalSearchParams } from 'expo-router';
import * as WebBrowser from 'expo-web-browser';
import { useEffect, useState } from 'react';
import { Share, StyleSheet, Text, View } from 'react-native';
import Animated from 'react-native-reanimated';

import { AIPanel } from '@/components/ai';
import { Icon } from '@/components/icon';
import { enter, PressableScale } from '@/components/motion';
import { ScoreRing, VerdictPill } from '@/components/result';
import { Screen } from '@/components/screen';
import { Button, Chip, ErrorText, Muted } from '@/components/ui';
import { Working } from '@/components/working';
import { api, SITE } from '@/lib/api';
import { startUrlScan } from '@/lib/scan';
import { ago, colors, fonts, tone, toneStyle } from '@/lib/theme';

const WORKING = ['pending', 'queued', 'running', 'processing', 'started'];
const STEPS = ['Resolving the address', 'Checking the certificate', 'Following redirects', 'Reading the page content',
  'Asking threat intelligence sources', 'Taking a safe screenshot'];

function severity(points: number) {
  if (points >= 20) return { label: 'High', color: colors.red };
  if (points >= 10) return { label: 'Medium', color: colors.amber };
  return { label: 'Low', color: colors.cyanSoft };
}

export default function ScanReport() {
  const { id } = useLocalSearchParams<{ id: string }>();
  const scanId = Number(id);
  const [report, setReport] = useState<any>(null);
  const [step, setStep] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [rescanning, setRescanning] = useState(false);

  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    const started = Date.now();
    const poll = async (tries: number) => {
      try {
        const s = await api.scanStatus(scanId);
        if (!alive) return;
        if (WORKING.includes((s.status || '').toLowerCase()) && tries < 100) {
          setStep(Math.min(STEPS.length - 1, Math.floor((Date.now() - started) / 6000)));
          timer = setTimeout(() => poll(tries + 1), 2500);
          return;
        }
        const full = await api.scan(scanId);
        if (!alive) return;
        setReport(full);
        const t = tone(full.raw_report?.aggregate_assessment?.verdict ?? full.verdict);
        if (tries > 0) {
          Haptics.notificationAsync(t === 'risk' ? Haptics.NotificationFeedbackType.Error
            : t === 'review' ? Haptics.NotificationFeedbackType.Warning : Haptics.NotificationFeedbackType.Success).catch(() => {});
        }
      } catch (e: any) {
        if (alive) setError(e.message);
      }
    };
    poll(0);
    return () => { alive = false; clearTimeout(timer); };
  }, [scanId]);

  const assessment = report?.raw_report?.aggregate_assessment;
  const verdict = assessment?.verdict ?? report?.verdict;
  const look = toneStyle[tone(verdict)];
  const reasons: any[] = [...(assessment?.reasons ?? [])].sort((a, b) => (b.deduction ?? 0) - (a.deduction ?? 0));
  const evidence = report ? JSON.stringify(report.raw_report ?? {}).length > 900000
    ? { url: report.url, verdict: report.verdict, assessment }
    : { url: report.url, verdict: report.verdict, ...(report.raw_report ?? {}) } : null;

  async function share() {
    const text = tone(verdict) === 'safe'
      ? `MyScanner found no threat on ${report.url} (${typeof assessment?.score === 'number' ? `score ${assessment.score}/100` : 'checked'}). Stay careful with links you were not expecting.`
      : `⚠️ Careful: MyScanner rated ${report.url} as "${look.label}". Do not open it or enter any details.`;
    Share.share({ message: `${text}\n\nChecked with MyScanner: ${SITE}` }).catch(() => {});
  }

  async function rescan() {
    setRescanning(true); setError(null);
    try { await startUrlScan(report.url, true); } catch (e: any) { setError(e.message); setRescanning(false); }
  }

  let host = report?.url ?? '';
  try { host = new URL(host).host || host; } catch {}
  const shareButton = report ? (
    <PressableScale accessibilityLabel="Share" onPress={share} style={st.round}><Icon name="share" size={18} color={colors.text} /></PressableScale>
  ) : null;

  return (
    <Screen back title={`Report #${scanId}`} eyebrow={`URL intelligence · report #${scanId}`} right={shareButton}
      largeTitle={report ? host : 'Scanning the link'} subtitle={report ? undefined : 'Usually under a minute. You can leave; the report is saved in History.'}>
      {report ? (
        <Animated.View entering={enter(0)} style={st.url}>
          <Icon name="link" size={15} color={colors.faint} />
          <Text selectable numberOfLines={2} style={{ flex: 1, color: colors.soft, fontSize: 13.5, fontFamily: fonts.regular }}>{report.url}</Text>
        </Animated.View>
      ) : null}
      <ErrorText>{error}</ErrorText>
      {!report && !error ? <Working steps={STEPS} step={step} /> : null}
      {report ? (
        <>
          <Animated.View entering={enter(1)} style={[st.card, { alignItems: 'center', gap: 14, borderColor: look.color + '44' }]}>
            <ScoreRing score={typeof assessment?.score === 'number' ? assessment.score : null} color={look.color} size={170} />
            <VerdictPill verdict={verdict} />
            <View style={{ flexDirection: 'row', flexWrap: 'wrap', gap: 6, justifyContent: 'center' }}>
              {assessment?.total_categories ? <Chip>{`${assessment.assessed_categories} of ${assessment.total_categories} checks`}</Chip> : null}
              {assessment?.sources?.length ? <Chip>{`${assessment.sources.length} sources`}</Chip> : null}
              {report.date ? <Chip>{ago(report.date)}</Chip> : null}
            </View>
            {assessment?.provisional ? <Muted center>Some checks were unavailable, so this result is provisional.</Muted> : null}
          </Animated.View>
          <Animated.View entering={enter(2)} style={{ flexDirection: 'row', gap: 10 }}>
            <Button label={tone(verdict) === 'safe' ? 'Share' : 'Warn others'} icon="share" onPress={share} flex={1.3} />
            <Button label="Rescan" icon="refresh" kind="secondary" onPress={rescan} busy={rescanning} flex={1} />
          </Animated.View>
          {evidence ? <Animated.View entering={enter(3)}><AIPanel tool="url" evidence={evidence} /></Animated.View> : null}
          {reasons.length ? (
            <View style={{ gap: 10 }}>
              <Text style={{ color: colors.text, fontSize: 21, fontFamily: fonts.bold, letterSpacing: -0.5, marginTop: 6 }}>What we found</Text>
              {reasons.slice(0, 10).map((r, i) => {
                const sev = severity(r.deduction ?? 0);
                return (
                  <Animated.View key={r.code ?? i} entering={enter(i + 3)} style={[st.finding, { borderLeftColor: sev.color }]}>
                    <Text style={{ color: sev.color, fontSize: 11, fontFamily: fonts.monoBold, letterSpacing: 1 }}>{sev.label.toUpperCase()}</Text>
                    <Text style={{ color: colors.text, fontSize: 14.5, lineHeight: 22, fontFamily: fonts.regular }}>{r.message}</Text>
                  </Animated.View>
                );
              })}
            </View>
          ) : null}
          {assessment?.missing_checks?.length ? (
            <Muted>{`Not checked: ${assessment.missing_checks.join(', ').replace(/_/g, ' ')}`}</Muted>
          ) : null}
          {assessment?.warning ? <Text style={{ color: colors.faint, fontSize: 12, fontFamily: fonts.regular }}>{assessment.warning}</Text> : null}
          <Button label="Full report on the website" icon="external" kind="secondary"
            onPress={() => WebBrowser.openBrowserAsync(`${SITE}/result/${scanId}`)} />
        </>
      ) : null}
    </Screen>
  );
}

const st = StyleSheet.create({
  round: { width: 40, height: 40, borderRadius: 20, alignItems: 'center', justifyContent: 'center', backgroundColor: 'rgba(17,35,56,.85)', borderWidth: 1, borderColor: '#2b4560' },
  url: { flexDirection: 'row', alignItems: 'center', gap: 10, padding: 13, borderRadius: 14, borderWidth: 1, borderColor: colors.line, backgroundColor: 'rgba(9,19,32,.85)' },
  card: { padding: 22, borderRadius: 26, borderWidth: 1, backgroundColor: 'rgba(14,24,37,.9)' },
  finding: { gap: 6, padding: 14, borderRadius: 16, borderWidth: 1, borderLeftWidth: 3, borderColor: colors.line, backgroundColor: '#0e1825' },
});
