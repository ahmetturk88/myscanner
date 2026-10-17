import { useEffect, useState } from 'react';
import { Text, View } from 'react-native';
import Animated, { FadeIn, ZoomIn } from 'react-native-reanimated';

import { Icon } from '@/components/icon';
import { enter, ScanOrb } from '@/components/motion';
import { colors, fonts } from '@/lib/theme';

/** Live progress: the radar, the current step, and a checklist that ticks off as time passes. */
export function Working({ steps, status, every = 5000, step: forced }: { steps: string[]; status?: string | null; every?: number; step?: number }) {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const timer = setInterval(() => setTick((t) => t + 1), every);
    return () => clearInterval(timer);
  }, [every]);
  const step = Math.min(steps.length - 1, forced ?? tick);
  return (
    <Animated.View entering={enter(0)} style={{ gap: 14, alignItems: 'center' }}>
      <View style={{ marginVertical: -26 }}><ScanOrb size={130} /></View>
      <Animated.Text key={step} entering={FadeIn.duration(400)} style={{ color: colors.text, fontSize: 18, fontFamily: fonts.bold, textAlign: 'center' }}>
        {steps[step]}…
      </Animated.Text>
      {status ? <Text style={{ color: colors.faint, fontSize: 12.5, fontFamily: fonts.mono }}>{status.toUpperCase()}</Text> : null}
      <View style={{ alignSelf: 'stretch', gap: 2, padding: 14, borderRadius: 20, borderWidth: 1, borderColor: colors.line, backgroundColor: 'rgba(14,24,37,.85)' }}>
        {steps.map((label, i) => {
          const done = i < step;
          const now = i === step;
          return (
            <View key={label} style={{ flexDirection: 'row', alignItems: 'center', gap: 12, paddingVertical: 8 }}>
              <View style={{ width: 24, height: 24, borderRadius: 12, alignItems: 'center', justifyContent: 'center', borderWidth: 1.5,
                borderColor: done ? colors.teal : now ? colors.cyan : '#2a4058', backgroundColor: done ? 'rgba(94,234,212,.15)' : 'transparent' }}>
                {done ? <Animated.View entering={ZoomIn.springify()}><Icon name="check" size={13} color={colors.teal} stroke={3} /></Animated.View>
                  : now ? <View style={{ width: 8, height: 8, borderRadius: 4, backgroundColor: colors.cyan }} /> : null}
              </View>
              <Text style={{ flex: 1, color: done ? colors.soft : now ? colors.text : colors.faint, fontSize: 14.5, fontFamily: now ? fonts.semibold : fonts.regular }}>{label}</Text>
            </View>
          );
        })}
      </View>
    </Animated.View>
  );
}
