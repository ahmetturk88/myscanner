import * as DocumentPicker from 'expo-document-picker';
import * as Haptics from 'expo-haptics';
import { useEffect, useRef, useState } from 'react';
import { Pressable, Text, View } from 'react-native';

import { AIPanel } from '@/components/ai';
import { Icon } from '@/components/icon';
import { Appear, ScanOrb } from '@/components/motion';
import { ResultCard } from '@/components/result';
import { Page, Steps, ToolRail } from '@/components/site';
import { ToolHero } from '@/components/tool-hero';
import { Button, Card, ErrorText } from '@/components/ui';
import { upload, waitForTask } from '@/lib/api';
import { colors, fonts, radius } from '@/lib/theme';
import { toolByName } from '@/lib/tools';

const TOOL = toolByName('file')!;

const TYPES = 'PDF, Word, Excel, ZIP, RAR, 7z, EXE, DLL, MSI and scripts, up to 10 MB';

export default function FileScanner() {
  const [file, setFile] = useState<DocumentPicker.DocumentPickerAsset | null>(null);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<string | null>(null);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const alive = useRef(true);
  useEffect(() => () => { alive.current = false; }, []);

  async function pick() {
    setError(null);
    const picked = await DocumentPicker.getDocumentAsync({ copyToCacheDirectory: true, multiple: false });
    if (picked.canceled || !picked.assets?.length) return;
    const asset = picked.assets[0];
    if (asset.size && asset.size > 10 * 1024 * 1024) { setError('This file is larger than 10 MB.'); return; }
    setFile(asset); setResult(null);
  }

  async function scan() {
    if (!file) return;
    setBusy(true); setError(null); setResult(null); setProgress('Uploading…');
    try {
      const queued: any = await upload('/tools/file', { uri: file.uri, name: file.name, mimeType: file.mimeType });
      const data = await waitForTask(queued.task_id, setProgress, () => alive.current);
      setResult(data);
      Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success).catch(() => {});
    } catch (e: any) {
      setError(e.message);
    } finally { setBusy(false); setProgress(null); }
  }

  return (
    <Page>
      <ToolRail active="file" />
      <ToolHero tool={TOOL} />
      <Pressable accessibilityRole="button" onPress={pick} disabled={busy}
        style={({ pressed }) => ({ borderRadius: radius.xl, borderWidth: 1.5, borderStyle: 'dashed', borderColor: pressed ? colors.cyan : colors.line2,
          backgroundColor: '#0e1726', padding: 26, alignItems: 'center', gap: 10 })}>
        <View style={{ width: 60, height: 60, borderRadius: 20, alignItems: 'center', justifyContent: 'center', backgroundColor: '#fb923c22', borderWidth: 1, borderColor: '#fb923c59' }}>
          <Icon name="file" size={28} color="#fb923c" />
        </View>
        <Text style={{ color: colors.text, fontSize: 16, fontFamily: fonts.bold, textAlign: 'center' }}>{file ? file.name : 'Choose a file'}</Text>
        <Text style={{ color: colors.faint, fontSize: 13, textAlign: 'center', fontFamily: fonts.regular }}>{file?.size ? `${(file.size / 1024).toFixed(0)} KB · tap to change` : TYPES}</Text>
      </Pressable>
      {busy ? (
        <Card style={{ alignItems: 'center' }}>
          <ScanOrb size={120} />
          <Text style={{ color: colors.soft, fontSize: 15, fontFamily: fonts.regular }}>{progress}</Text>
        </Card>
      ) : (
        <Button label="Analyze file" arrow="→" onPress={scan} disabled={!file} />
      )}
      <ErrorText>{error}</ErrorText>
      {result ? (
        <>
          <Appear><ResultCard result={result} title="File report" /></Appear>
          <Appear delay={120}><AIPanel tool="file" evidence={result} /></Appear>
        </>
      ) : null}
      <Steps steps={TOOL.steps} />
    </Page>
  );
}
