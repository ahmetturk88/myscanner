import { CameraView, useCameraPermissions } from 'expo-camera';
import * as Haptics from '@/lib/haptics';
import { router } from 'expo-router';
import { useEffect, useRef, useState } from 'react';
import { StyleSheet, Text, View } from 'react-native';
import Animated, { useAnimatedStyle, useSharedValue, withRepeat, withTiming, ZoomIn } from 'react-native-reanimated';
import { SafeAreaView } from 'react-native-safe-area-context';

import { HowItWorks } from '@/components/how';
import { Icon } from '@/components/icon';
import { Beam, enter, PressableScale } from '@/components/motion';
import { Screen } from '@/components/screen';
import { Accent, ToolBadge, ToolChips } from '@/components/tool-hero';
import { Button, ErrorText, Muted } from '@/components/ui';
import { startUrlScan } from '@/lib/scan';
import { colors, fonts } from '@/lib/theme';
import { toolByName } from '@/lib/tools';

const TOOL = toolByName('qr')!;

const FRAME = 250;

function Corners() {
  const k = useSharedValue(0);
  useEffect(() => { k.value = withRepeat(withTiming(1, { duration: 1300 }), -1, true); }, [k]);
  const breathe = useAnimatedStyle(() => ({ transform: [{ scale: 1 - 0.035 * k.value }], opacity: 0.75 + 0.25 * k.value }));
  const c = { position: 'absolute' as const, width: 42, height: 42, borderColor: colors.cyan };
  return (
    <Animated.View style={[StyleSheet.absoluteFill, breathe]}>
      <View style={[c, { top: 0, left: 0, borderTopWidth: 4, borderLeftWidth: 4, borderTopLeftRadius: 22 }]} />
      <View style={[c, { top: 0, right: 0, borderTopWidth: 4, borderRightWidth: 4, borderTopRightRadius: 22 }]} />
      <View style={[c, { bottom: 0, left: 0, borderBottomWidth: 4, borderLeftWidth: 4, borderBottomLeftRadius: 22 }]} />
      <View style={[c, { bottom: 0, right: 0, borderBottomWidth: 4, borderRightWidth: 4, borderBottomRightRadius: 22 }]} />
    </Animated.View>
  );
}

export default function QrScanner() {
  const [permission, requestPermission] = useCameraPermissions();
  const [code, setCode] = useState<string | null>(null);
  const [torch, setTorch] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const locked = useRef(false);

  if (!permission) return null;
  if (!permission.granted) {
    return (
      <Screen back title={TOOL.title} eyebrow={TOOL.kicker} badge={<ToolBadge tool={TOOL} busy />}
        largeTitle={<Accent text={TOOL.heading} accent={TOOL.accent} />} subtitle={TOOL.menu}>
        <ToolChips tool={TOOL} />
        <Animated.View entering={enter(2)} style={styles.card}>
          <Text style={{ color: colors.text, fontSize: 18, fontFamily: fonts.bold }}>Allow the camera</Text>
          <Muted>MyScanner uses the camera only to read QR codes. Nothing is recorded; only the text inside the code is used.</Muted>
          <Button label="Allow camera" arrow="→" onPress={requestPermission} />
        </Animated.View>
        <HowItWorks steps={TOOL.steps} />
      </Screen>
    );
  }

  const isLink = !!code && /^https?:\/\//i.test(code.trim());

  async function scanLink() {
    setBusy(true); setError(null);
    try { await startUrlScan(code!, true); } catch (e: any) { setError(e.message); setBusy(false); }
  }

  if (code) {
    return (
      <Screen back title="QR code" eyebrow="Decoded · not opened" largeTitle={isLink ? "Don't open it yet." : 'This code holds text.'}
        badge={
          <Animated.View entering={ZoomIn.springify()} style={{ width: 58, height: 58, borderRadius: 20, alignItems: 'center', justifyContent: 'center', marginBottom: 10,
            backgroundColor: (isLink ? colors.amber : colors.violet) + '18', borderWidth: 1, borderColor: (isLink ? colors.amber : colors.violet) + '55' }}>
            <Icon name={isLink ? 'alert' : 'qr'} size={27} color={isLink ? colors.amber : colors.violet} />
          </Animated.View>}>
        <Animated.View entering={enter(1)} style={styles.card}>
          <View style={{ padding: 12, borderRadius: 12, backgroundColor: colors.input, borderWidth: 1, borderColor: colors.line }}>
            <Text selectable style={{ color: colors.soft, fontSize: 15, lineHeight: 22, fontFamily: fonts.regular }}>{code}</Text>
          </View>
          <Muted>{isLink ? 'QR codes are a common way to hide phishing links. Check where it really leads first.' : 'It is not a web link, so there is nothing to scan online.'}</Muted>
          <ErrorText>{error}</ErrorText>
          {isLink ? <Button label="Inspect this URL" arrow="→" onPress={scanLink} busy={busy} /> : null}
          <Button label="Scan another code" icon="qr" kind="secondary" onPress={() => { locked.current = false; setCode(null); setError(null); }} />
        </Animated.View>
      </Screen>
    );
  }

  return (
    <View style={{ flex: 1, backgroundColor: '#000' }}>
      <CameraView style={StyleSheet.absoluteFill} facing="back" enableTorch={torch} barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
        onBarcodeScanned={({ data }) => {
          if (locked.current || !data) return;
          locked.current = true;
          Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success).catch(() => {});
          setCode(data);
        }} />
      <View pointerEvents="none" style={[StyleSheet.absoluteFill, { backgroundColor: 'rgba(4,7,15,.45)' }]} />
      <SafeAreaView style={{ flex: 1 }}>
        <View style={{ flexDirection: 'row', justifyContent: 'space-between', padding: 16 }}>
          <PressableScale accessibilityLabel="Close" onPress={() => router.back()} style={styles.round}>
            <Icon name="close" color="#fff" />
          </PressableScale>
          <PressableScale accessibilityLabel={torch ? 'Turn the light off' : 'Turn the light on'} onPress={() => setTorch(!torch)}
            style={[styles.round, torch && { backgroundColor: colors.cyan }]}>
            <Icon name="bolt" color={torch ? colors.onAccent : '#fff'} />
          </PressableScale>
        </View>
        <View style={{ flex: 1, alignItems: 'center', justifyContent: 'center', gap: 26 }}>
          <View style={{ width: FRAME, height: FRAME, overflow: 'hidden' }}>
            <Corners />
            <Beam height={FRAME} />
          </View>
          <Text style={{ color: '#fff', fontSize: 17, fontFamily: fonts.bold }}>Point the camera at a QR code</Text>
          <Text style={{ color: '#cbd5e1', fontSize: 14, textAlign: 'center', paddingHorizontal: 40, fontFamily: fonts.regular }}>We read it without opening it, so you can check it first.</Text>
        </View>
      </SafeAreaView>
    </View>
  );
}

const styles = StyleSheet.create({
  card: { gap: 14, padding: 18, borderRadius: 24, borderWidth: 1, borderColor: colors.line, backgroundColor: 'rgba(14,24,37,.9)' },
  round: { width: 46, height: 46, borderRadius: 23, alignItems: 'center', justifyContent: 'center', backgroundColor: 'rgba(15,31,51,.8)', borderWidth: 1, borderColor: 'rgba(255,255,255,.15)' },
});
