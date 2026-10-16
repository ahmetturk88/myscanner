import * as WebBrowser from 'expo-web-browser';
import { useLocalSearchParams } from 'expo-router';
import { useEffect, useState } from 'react';
import { ActivityIndicator, Text, View } from 'react-native';

import { AIPanel } from '@/components/ai';
import { Body, Button, Card, ErrorText, Muted, Screen, VerdictBadge } from '@/components/ui';
import { api, SITE } from '@/lib/api';
import { colors } from '@/lib/theme';

const WORKING = ['pending', 'queued', 'running', 'processing', 'started'];

export default function ScanReport() {
  const { id } = useLocalSearchParams<{ id: string }>();
  const scanId = Number(id);
  const [report, setReport] = useState<any>(null);
  const [status, setStatus] = useState('queued');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async (tries: number) => {
      try {
        const s = await api.scanStatus(scanId);
        if (!alive) return;
        setStatus(s.status);
        if (WORKING.includes((s.status || '').toLowerCase()) && tries < 100) {
          timer = setTimeout(() => poll(tries + 1), 3000);
          return;
        }
        const full = await api.scan(scanId);
        if (alive) setReport(full);
      } catch (e: any) {
        if (alive) setError(e.message);
      }
    };
    poll(0);
    return () => { alive = false; clearTimeout(timer); };
  }, [scanId]);

  const assessment = report?.raw_report?.aggregate_assessment;
  const evidence = report ? JSON.stringify(report.raw_report ?? {}).length > 900000
    ? { url: report.url, verdict: report.verdict, assessment }
    : { url: report.url, verdict: report.verdict, ...(report.raw_report ?? {}) } : null;

  return (
    <Screen>
      <Text selectable style={{ color: colors.text, fontSize: 18, fontWeight: '700' }}>{report?.url ?? `Report #${scanId}`}</Text>
      <ErrorText>{error}</ErrorText>
      {!report && !error ? (
        <Card style={{ alignItems: 'center', paddingVertical: 32 }}>
          <ActivityIndicator color={colors.cyan} size="large" />
          <Body>Checking the link… ({status})</Body>
          <Muted>This usually takes under a minute. You can leave this screen; the report is saved in History.</Muted>
        </Card>
      ) : null}
      {report ? (
        <>
          <Card>
            <VerdictBadge verdict={assessment?.verdict ?? report.verdict} score={assessment?.score} />
            {assessment?.provisional ? <Muted>Some checks were unavailable, so this result is provisional.</Muted> : null}
            {(assessment?.reasons ?? []).slice(0, 8).map((r: any) => (
              <Text key={r.code} style={{ color: colors.text, fontSize: 15, lineHeight: 22 }}>{'•  '}{r.message}</Text>
            ))}
            {assessment?.missing_checks?.length ? <Muted>{`Not checked: ${assessment.missing_checks.join(', ').replace(/_/g, ' ')}`}</Muted> : null}
            {assessment?.warning ? <Text style={{ color: colors.faint, fontSize: 12 }}>{assessment.warning}</Text> : null}
          </Card>
          {evidence ? <AIPanel tool="url" evidence={evidence} /> : null}
          <Button label="Open the full report on the website" kind="secondary" onPress={() => WebBrowser.openBrowserAsync(`${SITE}/result/${scanId}`)} />
        </>
      ) : null}
      <View style={{ height: 8 }} />
    </Screen>
  );
}
