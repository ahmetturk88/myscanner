import * as Haptics from 'expo-haptics';
import { useLocalSearchParams } from 'expo-router';
import * as WebBrowser from 'expo-web-browser';
import { useEffect, useState } from 'react';
import { Pressable, Share, Text, View } from 'react-native';

import { AIPanel } from '@/components/ai';
import { Icon } from '@/components/icon';
import { Appear, Gauge, ScanOrb } from '@/components/motion';
import { Button, Card, Chip, ErrorText, Header, Muted, Screen, Section } from '@/components/ui';
import { api, SITE } from '@/lib/api';
import { startUrlScan } from '@/lib/scan';
import { ago, colors, tone, toneStyle } from '@/lib/theme';

const WORKING = ['pending', 'queued', 'running', 'processing', 'started'];
const STEPS = ['Resolving the address', 'Checking the certificate', 'Following redirects', 'Reading the page content',
  'Asking threat intelligence sources', 'Taking a safe screenshot'];

function severity(points: number) {
  if (points >= 20) return { label: 'High', color: colors.red };
  if (points >= 10) return { label: 'Medium', color: colors.amber };
  return { label: 'Low', color: colors.cyanSoft };
}

function Scanning({ url, step }: { url?: string; step: number }) {
  return (
    <View style={{ gap: 14 }}>
      <View style={{ alignItems: 'center', marginTop: -10 }}><ScanOrb /></View>
      {url ? <Text selectable style={{ color: colors.text, fontSize: 16, fontWeight: '700', textAlign: 'center' }}>{url}</Text> : null}
      <Muted center>Usually under a minute. You can leave this screen; the report is saved in History.</Muted>
      <Card>
        {STEPS.map((label, i) => {
          const state = i < step ? 'seen' : i === step ? 'now' : 'next';
          return (
            <View key={label} style={{ flexDirection: 'row', alignItems: 'center', gap: 12, paddingVertical: 4 }}>
              <View style={{ width: 22, height: 22, borderRadius: 11, alignItems: 'center', justifyContent: 'center', borderWidth: 2,
                borderColor: state === 'next' ? colors.line2 : colors.cyan, backgroundColor: state === 'seen' ? colors.cyan + '33' : 'transparent' }}>
                {state === 'now' ? <View style={{ width: 8, height: 8, borderRadius: 4, backgroundColor: colors.cyan }} /> : null}
              </View>
              <Text style={{ color: state === 'next' ? '#5b6f88' : state === 'now' ? colors.text : colors.soft, fontSize: 15,
                fontWeight: state === 'now' ? '800' : '500' }}>{label}</Text>
            </View>
          );
        })}
      </Card>
    </View>
  );
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

  return (
    <Screen>
      <Header title={report ? 'Report' : 'Scanning'} right={report ? (
        <Pressable accessibilityRole="button" accessibilityLabel="Share" onPress={share} hitSlop={10}><Icon name="share" color={colors.muted} /></Pressable>
      ) : null} />
      <ErrorText>{error}</ErrorText>
      {!report && !error ? <Scanning step={step} /> : null}
      {report ? (
        <>
          <Appear>
            <View style={{ alignItems: 'center', gap: 10 }}>
              <View style={{ alignItems: 'center', justifyContent: 'center' }}>
                <Gauge score={typeof assessment?.score === 'number' ? assessment.score : null} color={look.color} />
                <View style={{ position: 'absolute', alignItems: 'center' }}>
                  <Text style={{ color: look.color, fontSize: 46, fontWeight: '800', lineHeight: 50 }}>{typeof assessment?.score === 'number' ? assessment.score : '—'}</Text>
                  <Text style={{ color: colors.faint }}>/100</Text>
                </View>
              </View>
              <View style={{ flexDirection: 'row', alignItems: 'center', gap: 8, paddingVertical: 8, paddingHorizontal: 14, borderRadius: 999,
                backgroundColor: look.color + '18', borderWidth: 1, borderColor: look.color + '66' }}>
                <Icon name={tone(verdict) === 'safe' ? 'check' : 'alert'} size={18} color={look.color} />
                <Text style={{ color: look.color, fontSize: 16, fontWeight: '800' }}>{look.label}</Text>
              </View>
              <Text selectable style={{ color: colors.text, fontSize: 16, fontWeight: '700', textAlign: 'center' }}>{report.url}</Text>
              <View style={{ flexDirection: 'row', flexWrap: 'wrap', gap: 6, justifyContent: 'center' }}>
                {assessment?.total_categories ? <Chip>{`${assessment.assessed_categories} of ${assessment.total_categories} checks`}</Chip> : null}
                {assessment?.sources?.length ? <Chip>{`${assessment.sources.length} sources`}</Chip> : null}
                {report.date ? <Chip>{ago(report.date)}</Chip> : null}
              </View>
              {assessment?.provisional ? <Muted center>Some checks were unavailable, so this result is provisional.</Muted> : null}
            </View>
          </Appear>
          {evidence ? <Appear delay={120}><AIPanel tool="url" evidence={evidence} /></Appear> : null}
          {reasons.length ? (
            <Appear delay={200}>
              <View style={{ gap: 10 }}>
                <Section>What we found</Section>
                <Card style={{ gap: 0, paddingVertical: 6 }}>
                  {reasons.slice(0, 10).map((r, i) => {
                    const s = severity(r.deduction ?? 0);
                    return (
                      <View key={r.code ?? i} style={{ flexDirection: 'row', gap: 10, paddingVertical: 11, borderTopWidth: i ? 1 : 0, borderTopColor: colors.line }}>
                        <Text style={{ color: s.color, backgroundColor: s.color + '22', fontSize: 11, fontWeight: '800', paddingVertical: 3,
                          paddingHorizontal: 8, borderRadius: 7, overflow: 'hidden', alignSelf: 'flex-start' }}>{s.label}</Text>
                        <Text style={{ flex: 1, color: colors.text, fontSize: 14.5, lineHeight: 21 }}>{r.message}</Text>
                      </View>
                    );
                  })}
                </Card>
              </View>
            </Appear>
          ) : null}
          {assessment?.missing_checks?.length ? (
            <Muted>{`Not checked: ${assessment.missing_checks.join(', ').replace(/_/g, ' ')}`}</Muted>
          ) : null}
          {assessment?.warning ? <Text style={{ color: colors.faint, fontSize: 12 }}>{assessment.warning}</Text> : null}
          <View style={{ flexDirection: 'row', gap: 10 }}>
            <Button label="Rescan" icon="refresh" kind="secondary" onPress={rescan} busy={rescanning} flex={1} />
            <Button label={tone(verdict) === 'safe' ? 'Share' : 'Share warning'} icon="share" onPress={share} flex={1.3} />
          </View>
          <Button label="Full report on the website" icon="external" kind="secondary"
            onPress={() => WebBrowser.openBrowserAsync(`${SITE}/result/${scanId}`)} />
        </>
      ) : null}
    </Screen>
  );
}
