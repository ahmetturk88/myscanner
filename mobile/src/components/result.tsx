import { Text, View } from 'react-native';

import { Details } from '@/components/details';
import { Card, VerdictBadge } from '@/components/ui';
import { colors } from '@/lib/theme';

/** Pick a verdict-like value and score from any tool's result. */
export function headline(result: any): { verdict?: string; score?: number } {
  if (result?.local_strength) {
    // Password checks: an exposed password is the headline; otherwise its strength.
    const exposed = result.verdict === 'exposed';
    return { verdict: exposed ? 'exposed' : result.local_strength.strength, score: result.local_strength.score };
  }
  const verdict = result?.verdict ?? result?.risk_level ?? result?.assessment?.verdict
    ?? result?.overall_assessment?.verdict ?? result?.summary?.verdict;
  const score = [result?.score, result?.risk_score, result?.final?.score, result?.assessment?.score, result?.security_score]
    .find((s) => typeof s === 'number');
  return { verdict: typeof verdict === 'string' ? verdict : undefined, score };
}

export function ResultCard({ result, title }: { result: any; title: string }) {
  const top = headline(result);
  return (
    <Card>
      <Text style={{ color: colors.faint, fontSize: 12, fontWeight: '800', letterSpacing: 1.5 }}>{title.toUpperCase()}</Text>
      {top.verdict ? <VerdictBadge verdict={top.verdict} score={top.score} big /> : null}
      <View style={{ height: 1, backgroundColor: colors.line }} />
      <Details data={result} />
    </Card>
  );
}
