import { Text, View } from 'react-native';
import Animated, { ZoomIn } from 'react-native-reanimated';

import { Details } from '@/components/details';
import { Icon } from '@/components/icon';
import { enter, Gauge, useCountUp } from '@/components/motion';
import { colors, fonts, tone, verdictStyle } from '@/lib/theme';

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

/** Score ring that fills while its number counts up. */
export function ScoreRing({ score, color, size = 150 }: { score: number | null; color: string; size?: number }) {
  const n = useCountUp(score, 1100);
  return (
    <View style={{ alignItems: 'center', justifyContent: 'center' }}>
      <Gauge score={score} color={color} size={size} />
      <View style={{ position: 'absolute', alignItems: 'center' }}>
        <Text style={{ color, fontSize: size * 0.27, fontFamily: fonts.bold, lineHeight: size * 0.32 }}>{n ?? '—'}</Text>
        <Text style={{ color: colors.faint, fontFamily: fonts.mono, fontSize: 12 }}>/100</Text>
      </View>
    </View>
  );
}

/** The verdict as a pill that pops in. */
export function VerdictPill({ verdict }: { verdict?: string | null }) {
  const look = verdictStyle(verdict);
  const t = tone(verdict);
  return (
    <Animated.View entering={ZoomIn.delay(250).springify()} style={{ flexDirection: 'row', alignItems: 'center', gap: 8, paddingVertical: 8, paddingHorizontal: 15,
      borderRadius: 999, backgroundColor: look.color + '18', borderWidth: 1, borderColor: look.color + '66' }}>
      <Icon name={t === 'safe' ? 'check' : t === 'unknown' ? 'shield' : 'alert'} size={17} color={look.color} />
      <Text style={{ color: look.color, fontSize: 16, fontFamily: fonts.bold }}>{look.label}</Text>
    </Animated.View>
  );
}

export function ResultCard({ result, title }: { result: any; title: string }) {
  const top = headline(result);
  const look = verdictStyle(top.verdict);
  return (
    <Animated.View entering={enter(0)} style={{ gap: 16, padding: 20, borderRadius: 24, borderWidth: 1, borderColor: look.color + '44', backgroundColor: 'rgba(14,24,37,.92)' }}>
      <Text style={{ color: colors.cyan, fontFamily: fonts.mono, fontSize: 12, letterSpacing: 2 }}>{title.toUpperCase()}</Text>
      {top.verdict || typeof top.score === 'number' ? (
        <View style={{ alignItems: 'center', gap: 12 }}>
          {typeof top.score === 'number' ? <ScoreRing score={top.score} color={look.color} size={130} /> : null}
          {top.verdict ? <VerdictPill verdict={top.verdict} /> : null}
        </View>
      ) : null}
      <View style={{ height: 1, backgroundColor: colors.line }} />
      <Details data={result} />
    </Animated.View>
  );
}
