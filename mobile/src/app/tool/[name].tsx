import * as Haptics from 'expo-haptics';
import { useLocalSearchParams } from 'expo-router';
import { useEffect, useRef, useState } from 'react';
import { ActivityIndicator, Text, View } from 'react-native';

import { AIPanel } from '@/components/ai';
import { Appear } from '@/components/motion';
import { ResultCard } from '@/components/result';
import { Page, Steps, ToolRail } from '@/components/site';
import { ToolHero } from '@/components/tool-hero';
import { Button, Card, ErrorText, Field, Muted } from '@/components/ui';
import { api, waitForTask } from '@/lib/api';
import { colors, fonts } from '@/lib/theme';
import { toolByName } from '@/lib/tools';

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

  if (!tool || !tool.field || !tool.body) return <Page><ErrorText>Unknown tool.</ErrorText></Page>;
  const { field, body } = tool;

  async function run() {
    setBusy(true); setError(null); setResult(null); setProgress(null);
    try {
      let data: any = await api.tool(tool!.name, body(value.trim()));
      if (data?.task_id) data = await waitForTask(data.task_id, setProgress, () => alive.current);
      if (field.secure) setValue('');
      setResult(data);
      Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success).catch(() => {});
    } catch (e: any) {
      setError(e.message);
    } finally { setBusy(false); setProgress(null); }
  }

  return (
    <Page>
      <ToolRail active={tool.name} />
      <ToolHero tool={tool} />
      <Card>
        <Field label={field.label} value={value} onChangeText={setValue} placeholder={field.placeholder}
          secureTextEntry={field.secure} autoCapitalize="none" autoCorrect={false} keyboardType={field.keyboard ?? 'default'}
          onSubmitEditing={run} returnKeyType="go" />
        <Button label={tool.action ?? 'Analyze'} arrow="→" onPress={run} busy={busy} disabled={!value.trim()} />
        {field.secure ? <Muted>Sent over HTTPS for analysis and never stored. Only a short hash prefix is used for the breach check.</Muted> : null}
        {busy && progress ? (
          <View style={{ flexDirection: 'row', gap: 10, alignItems: 'center' }}>
            <ActivityIndicator color={colors.cyan} />
            <Text style={{ color: colors.soft, fontFamily: fonts.regular }}>{progress}</Text>
          </View>
        ) : null}
        <ErrorText>{error}</ErrorText>
        <Muted>The result describes evidence and coverage, not a probability of safety.</Muted>
      </Card>
      {result ? (
        <>
          <Appear><ResultCard result={result} title="Assessment" /></Appear>
          <Appear delay={120}><AIPanel tool={tool.aiTool} evidence={result} /></Appear>
        </>
      ) : null}
      <Steps steps={tool.steps} />
    </Page>
  );
}
