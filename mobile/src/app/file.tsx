import * as DocumentPicker from 'expo-document-picker';
import * as Haptics from '@/lib/haptics';
import { useEffect, useRef, useState } from 'react';
import { Text, View } from 'react-native';
import Animated, { useAnimatedStyle, useSharedValue, withRepeat, withTiming } from 'react-native-reanimated';

import { AIPanel } from '@/components/ai';
import { Evidence } from '@/components/evidence';
import { HowItWorks } from '@/components/how';
import { Icon } from '@/components/icon';
import { enter, PressableScale } from '@/components/motion';
import { hasPlain, PlainReport, reportOf, withoutPlain } from '@/components/report';
import { ResultCard } from '@/components/result';
import { Screen } from '@/components/screen';
import { Accent, ToolBadge, ToolChips } from '@/components/tool-hero';
import { Button, ErrorText } from '@/components/ui';
import { Working } from '@/components/working';
import { upload, waitForTask } from '@/lib/api';
import { t } from '@/lib/i18n';
import { colors, fonts } from '@/lib/theme';
import { toolByName } from '@/lib/tools';

const steps = () => [t('Uploading the file securely'), t('Fingerprinting the file'), t('Inspecting its structure'), t('Checking hash reputation')];

/** The drop zone's icon bobs gently until a file is chosen. */
function Floating({ children, active }: { children: React.ReactNode; active: boolean }) {
  const y = useSharedValue(0);
  useEffect(() => { y.value = active ? withRepeat(withTiming(1, { duration: 1400 }), -1, true) : withTiming(0); }, [active, y]);
  const style = useAnimatedStyle(() => ({ transform: [{ translateY: -6 * y.value }] }));
  return <Animated.View style={style}>{children}</Animated.View>;
}

export default function FileScanner() {
  const TOOL = toolByName('file')!;
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
    if (asset.size && asset.size > 10 * 1024 * 1024) { setError(t('This file is larger than 10 MB.')); return; }
    setFile(asset); setResult(null);
  }

  async function scan() {
    if (!file) return;
    setBusy(true); setError(null); setResult(null); setProgress(t('Uploading'));
    try {
      const queued: any = await upload('/tools/file', { uri: file.uri, name: file.name, mimeType: file.mimeType });
      let data = await waitForTask(queued.task_id, setProgress, () => alive.current);
      data = reportOf(data);
      setResult(data);
      if (!hasPlain(data?.plain)) Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success).catch(() => {});
    } catch (e: any) {
      setError(e.message);
    } finally { setBusy(false); setProgress(null); }
  }

  return (
    <Screen back title={TOOL.title} eyebrow={TOOL.kicker} badge={<ToolBadge tool={TOOL} busy={busy} />}
      largeTitle={<Accent text={TOOL.heading} accent={TOOL.accent} />} subtitle={TOOL.menu}>
      <ToolChips tool={TOOL} />
      <Animated.View entering={enter(2)}>
        <PressableScale scale={0.98} onPress={pick} disabled={busy}
          style={{ borderRadius: 24, borderWidth: 1.5, borderStyle: 'dashed', borderColor: file ? colors.teal : colors.line2,
            backgroundColor: 'rgba(14,24,37,.9)', padding: 26, alignItems: 'center', gap: 10 }}>
          <Floating active={!file}>
            <View style={{ width: 62, height: 62, borderRadius: 20, alignItems: 'center', justifyContent: 'center',
              backgroundColor: file ? 'rgba(94,234,212,.1)' : 'rgba(119,220,255,.08)', borderWidth: 1, borderColor: file ? 'rgba(94,234,212,.4)' : 'rgba(119,220,255,.3)' }}>
              <Icon name={file ? 'check' : 'file'} size={28} color={file ? colors.teal : colors.cyan} />
            </View>
          </Floating>
          <Text style={{ color: colors.text, fontSize: 16, fontFamily: fonts.bold, textAlign: 'center' }} numberOfLines={2}>{file ? file.name : t('Choose a file')}</Text>
          <Text style={{ color: colors.faint, fontSize: 13, textAlign: 'center', fontFamily: fonts.regular }}>{file?.size ? t('{size} KB · tap to change', { size: (file.size / 1024).toFixed(0) }) : t('PDF, Office, archives, apps and scripts · up to 10 MB')}</Text>
        </PressableScale>
      </Animated.View>
      {!busy ? <Button label={t('Analyze file')} arrow="→" onPress={scan} disabled={!file} /> : null}
      <ErrorText>{error}</ErrorText>
      {busy ? <Working steps={steps()} status={progress} every={3500} /> : null}
      {result && hasPlain(result.plain) ? (
        <PlainReport plain={result.plain} haptic again={{ label: t('Check another file'), icon: 'file', onPress: () => { setResult(null); setFile(null); pick(); } }}>
          <Animated.View entering={enter(6)}><AIPanel tool="file" evidence={result} /></Animated.View>
          <Evidence data={withoutPlain(result)} start={7} />
        </PlainReport>
      ) : result ? (
        <>
          <ResultCard result={result} title={t('File report')} />
          <Animated.View entering={enter(2)}><AIPanel tool="file" evidence={result} /></Animated.View>
          <Evidence data={result} start={3} />
        </>
      ) : null}
      {!busy && !result ? <HowItWorks steps={TOOL.steps} /> : null}
    </Screen>
  );
}
