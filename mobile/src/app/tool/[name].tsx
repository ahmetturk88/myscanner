import * as Haptics from 'expo-haptics';
import { useLocalSearchParams } from 'expo-router';
import { useEffect, useRef, useState } from 'react';
import { ActivityIndicator, Text, View } from 'react-native';

import { AIPanel } from '@/components/ai';
import { Icon } from '@/components/icon';
import { Appear } from '@/components/motion';
import { ResultCard } from '@/components/result';
import { Button, Card, ErrorText, Field, Header, Muted, Screen } from '@/components/ui';
import { api, waitForTask } from '@/lib/api';
import { colors } from '@/lib/theme';
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

  if (!tool || !tool.field || !tool.body) return <Screen><Header title="Tool" /><ErrorText>Unknown tool.</ErrorText></Screen>;
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
    <Screen>
      <Header title={tool.title} />
      <View style={{ flexDirection: 'row', alignItems: 'center', gap: 14 }}>
        <View style={{ width: 58, height: 58, borderRadius: 19, alignItems: 'center', justifyContent: 'center',
          backgroundColor: tool.color + '22', borderWidth: 1, borderColor: tool.color + '59' }}>
          <Icon name={tool.icon} size={26} color={tool.color} />
        </View>
        <Text style={{ flex: 1, color: colors.muted, fontSize: 15, lineHeight: 21 }}>{tool.hint}</Text>
      </View>
      <Card>
        <Field label={field.label} value={value} onChangeText={setValue} placeholder={field.placeholder} icon={tool.icon}
          secureTextEntry={field.secure} autoCapitalize="none" autoCorrect={false} keyboardType={field.keyboard ?? 'default'}
          onSubmitEditing={run} returnKeyType="go" />
        {field.secure ? <Muted>Sent over HTTPS for analysis and never stored. Only a short hash prefix is used for the breach check.</Muted> : null}
        <Button label="Check" icon="shield" onPress={run} busy={busy} disabled={!value.trim()} />
        {busy && progress ? (
          <View style={{ flexDirection: 'row', gap: 10, alignItems: 'center' }}>
            <ActivityIndicator color={colors.cyan} /><Text style={{ color: colors.soft }}>{progress}</Text>
          </View>
        ) : null}
        <ErrorText>{error}</ErrorText>
      </Card>
      {result ? (
        <>
          <Appear><ResultCard result={result} title="Result" /></Appear>
          <Appear delay={120}><AIPanel tool={tool.aiTool} evidence={result} /></Appear>
        </>
      ) : null}
    </Screen>
  );
}
