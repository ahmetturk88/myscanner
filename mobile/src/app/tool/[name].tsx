import { Stack, useLocalSearchParams } from 'expo-router';
import { useEffect, useRef, useState } from 'react';
import { ActivityIndicator } from 'react-native';

import { AIPanel } from '@/components/ai';
import { Details } from '@/components/details';
import { Body, Button, Card, ErrorText, Field, Muted, Screen, VerdictBadge } from '@/components/ui';
import { api, request } from '@/lib/api';
import { colors } from '@/lib/theme';
import { toolByName } from '@/lib/tools';

/** Pick a verdict-like value from any tool's result. */
function headline(result: any): { verdict?: string; score?: number } {
  const verdict = result?.verdict ?? result?.risk_level ?? result?.assessment?.verdict ?? result?.final?.strength ?? result?.status;
  const score = [result?.score, result?.risk_score, result?.final?.score, result?.assessment?.score].find((s) => typeof s === 'number');
  return { verdict: typeof verdict === 'string' ? verdict : undefined, score };
}

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

  if (!tool) return <Screen><ErrorText>Unknown tool.</ErrorText></Screen>;

  async function waitFor(taskId: string) {
    for (let i = 0; i < 120 && alive.current; i++) {
      const task: any = await request(`/tasks/${encodeURIComponent(taskId)}`);
      if (task.state === 'SUCCESS') return task.result;
      if (task.state === 'FAILURE') throw new Error(task.error || 'Analysis failed. Please retry.');
      setProgress(task.status || 'Working…');
      await new Promise((r) => setTimeout(r, 2500));
    }
    throw new Error('This is taking longer than usual. Please try again later.');
  }

  async function run() {
    setBusy(true); setError(null); setResult(null); setProgress(null);
    try {
      let data: any = await api.tool(tool!.name, tool!.body(value.trim()));
      if (data?.task_id) data = await waitFor(data.task_id);
      if (tool!.field.secure) setValue('');
      setResult(data);
    } catch (e: any) {
      setError(e.message);
    } finally { setBusy(false); setProgress(null); }
  }

  const top = headline(result);
  return (
    <Screen>
      <Stack.Screen options={{ title: tool.title }} />
      <Muted>{tool.hint}</Muted>
      <Card>
        <Field label={tool.field.label} value={value} onChangeText={setValue} placeholder={tool.field.placeholder}
          secureTextEntry={tool.field.secure} autoCapitalize="none" autoCorrect={false} keyboardType={tool.field.keyboard ?? 'default'}
          onSubmitEditing={run} returnKeyType="go" />
        {tool.field.secure ? <Muted>Sent over HTTPS for analysis and never stored. Only a short hash prefix is used for the breach check.</Muted> : null}
        <ErrorText>{error}</ErrorText>
        <Button label="Check" onPress={run} busy={busy} disabled={!value.trim()} />
        {busy && progress ? <><ActivityIndicator color={colors.cyan} /><Body>{progress}</Body></> : null}
      </Card>
      {result ? (
        <>
          <Card>
            {top.verdict ? <VerdictBadge verdict={top.verdict} score={top.score} /> : null}
            <Details data={result} />
          </Card>
          <AIPanel tool={tool.aiTool} evidence={result} />
        </>
      ) : null}
    </Screen>
  );
}
