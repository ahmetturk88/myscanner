import * as Haptics from '@/lib/haptics';
import { useLocalSearchParams } from 'expo-router';
import { useEffect, useRef, useState } from 'react';
import { Text, View } from 'react-native';
import Animated from 'react-native-reanimated';

import { AIPanel } from '@/components/ai';
import { Evidence } from '@/components/evidence';
import { HowItWorks } from '@/components/how';
import { enter } from '@/components/motion';
import { hasPlain, PlainReport, reportOf, withoutPlain } from '@/components/report';
import { ResultCard } from '@/components/result';
import { Screen } from '@/components/screen';
import { Accent, ToolBadge, ToolChips } from '@/components/tool-hero';
import { Button, ErrorText, Field, Muted } from '@/components/ui';
import { Working } from '@/components/working';
import { api, waitForTask } from '@/lib/api';
import { colors, fonts } from '@/lib/theme';
import { toolByName } from '@/lib/tools';

const STEPS = ['Sending the request securely', 'Collecting the evidence', 'Checking available sources', 'Building your report'];

export default function ToolScreen() {
  const { name } = useLocalSearchParams<{ name: string }>();
  const tool = toolByName(name);
  const [value, setValue] = useState('');
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<string | null>(null);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const alive = useRef(true);
  useEffect(() => () => { alive.current = false; }, []);

  if (!tool || !tool.field || !tool.body) return <Screen back title="Tool"><ErrorText>Unknown tool.</ErrorText></Screen>;
  const { field, body } = tool;

  async function run() {
    if (!value.trim()) return;
    setBusy(true); setError(null); setResult(null); setProgress(null);
    try {
      let data: any = await api.tool(tool!.name, body(value.trim()));
      if (data?.task_id) data = await waitForTask(data.task_id, setProgress, () => alive.current);
      if (field.secure) setValue('');
      data = reportOf(data);
      setResult(data);
      // A summary buzzes by its verdict; older servers without one get the plain success buzz.
      if (!hasPlain(data?.plain)) Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success).catch(() => {});
    } catch (e: any) {
      setError(e.message);
      Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error).catch(() => {});
    } finally { setBusy(false); setProgress(null); }
  }

  return (
    <Screen back title={tool.title} eyebrow={tool.kicker} badge={<ToolBadge tool={tool} busy={busy} />}
      largeTitle={<Accent text={tool.heading} accent={tool.accent} />} subtitle={tool.menu}>
      <ToolChips tool={tool} />
      <Animated.View entering={enter(2)} style={{ gap: 14, padding: 18, borderRadius: 24, borderWidth: 1, borderColor: colors.line, backgroundColor: 'rgba(14,24,37,.9)' }}>
        <Field label={field.label} value={value} onChangeText={setValue} placeholder={field.placeholder}
          secureTextEntry={field.secure} autoCapitalize="none" autoCorrect={false} keyboardType={field.keyboard ?? 'default'}
          onSubmitEditing={run} returnKeyType="go" editable={!busy} />
        <Button label={tool.action ?? 'Analyze'} arrow="→" onPress={run} busy={busy} disabled={!value.trim()} />
        {field.secure ? <Muted>Sent over HTTPS and never stored. Only a short hash prefix is used for the breach check.</Muted> : null}
        <ErrorText>{error}</ErrorText>
      </Animated.View>
      {busy ? <Working steps={STEPS} status={progress} every={3500} /> : null}
      {result && hasPlain(result.plain) ? (
        <PlainReport plain={result.plain} haptic plainShare={tool.name !== 'email'}
          again={{ label: 'Check another', onPress: () => { setResult(null); setValue(''); } }}>
          <Animated.View entering={enter(6)}><AIPanel tool={tool.aiTool} evidence={result} /></Animated.View>
          <Evidence data={withoutPlain(result)} start={7} />
        </PlainReport>
      ) : result ? (
        <>
          <ResultCard result={result} title="Assessment" />
          <Animated.View entering={enter(2)}><AIPanel tool={tool.aiTool} evidence={result} /></Animated.View>
          <Evidence data={result} start={3} />
          <Text style={{ color: colors.faint, fontSize: 12.5, lineHeight: 19, fontFamily: fonts.regular, textAlign: 'center' }}>
            The result describes evidence and coverage, not a guarantee of safety.
          </Text>
        </>
      ) : null}
      {!busy && !result ? <View><HowItWorks steps={tool.steps} /></View> : null}
    </Screen>
  );
}
