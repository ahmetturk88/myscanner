import { CameraView, useCameraPermissions } from 'expo-camera';
import * as Haptics from 'expo-haptics';
import { router } from 'expo-router';
import { useRef, useState } from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

import { Icon } from '@/components/icon';
import { Appear, Beam } from '@/components/motion';
import { Page, Steps, ToolRail } from '@/components/site';
import { ToolHero } from '@/components/tool-hero';
import { Button, Card, ErrorText, Muted } from '@/components/ui';
import { startUrlScan } from '@/lib/scan';
import { colors, fonts } from '@/lib/theme';
import { toolByName } from '@/lib/tools';

const TOOL = toolByName('qr')!;

const FRAME = 250;

function Corners() {
  const c = { position: 'absolute' as const, width: 42, height: 42, borderColor: colors.cyan };
  return (
    <>
      <View style={[c, { top: 0, left: 0, borderTopWidth: 4, borderLeftWidth: 4, borderTopLeftRadius: 22 }]} />
      <View style={[c, { top: 0, right: 0, borderTopWidth: 4, borderRightWidth: 4, borderTopRightRadius: 22 }]} />
      <View style={[c, { bottom: 0, left: 0, borderBottomWidth: 4, borderLeftWidth: 4, borderBottomLeftRadius: 22 }]} />
      <View style={[c, { bottom: 0, right: 0, borderBottomWidth: 4, borderRightWidth: 4, borderBottomRightRadius: 22 }]} />
    </>
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
      <Page>
        <ToolRail active="qr" />
        <ToolHero tool={TOOL} />
        <Card>
          <Icon name="qr" size={30} color={colors.cyan} />
          <Text style={{ color: colors.text, fontSize: 18, fontFamily: fonts.bold }}>Allow the camera</Text>
          <Muted>MyScanner uses the camera only to read QR codes. Nothing is recorded; only the text inside the code is used.</Muted>
          <Button label="Allow camera" arrow="→" onPress={requestPermission} />
        </Card>
        <Steps steps={TOOL.steps} />
      </Page>
    );
  }

  const isLink = !!code && /^https?:\/\//i.test(code.trim());

  async function scanLink() {
    setBusy(true); setError(null);
    try { await startUrlScan(code!, true); } catch (e: any) { setError(e.message); setBusy(false); }
  }

  if (code) {
    return (
      <Page>
        <ToolRail active="qr" />
        <Appear>
          <Card>
            <View style={{ flexDirection: 'row', alignItems: 'center', gap: 10 }}>
              <Icon name={isLink ? 'alert' : 'qr'} size={22} color={isLink ? colors.amber : colors.violet} />
              <Text style={{ color: colors.text, fontSize: 18, fontFamily: fonts.bold }}>{isLink ? "Don't open it yet" : 'This code contains text'}</Text>
            </View>
            <View style={{ padding: 12, borderRadius: 12, backgroundColor: colors.input, borderWidth: 1, borderColor: colors.line }}>
              <Text selectable style={{ color: colors.soft, fontSize: 15, lineHeight: 22, fontFamily: fonts.regular }}>{code}</Text>
            </View>
            <Muted>{isLink ? 'QR codes are a common way to hide phishing links. Check where it really leads first.' : 'It is not a web link, so there is nothing to scan online.'}</Muted>
            <ErrorText>{error}</ErrorText>
            {isLink ? <Button label="Inspect this URL" arrow="→" onPress={scanLink} busy={busy} /> : null}
            <Button label="Scan another code" icon="qr" kind="secondary" onPress={() => { locked.current = false; setCode(null); setError(null); }} />
          </Card>
        </Appear>
        <Steps steps={TOOL.steps} />
      </Page>
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
          <Pressable accessibilityRole="button" accessibilityLabel="Close" onPress={() => router.back()} style={styles.round}>
            <Icon name="close" color="#fff" />
          </Pressable>
          <Pressable accessibilityRole="button" accessibilityLabel={torch ? 'Turn the light off' : 'Turn the light on'} onPress={() => setTorch(!torch)}
            style={[styles.round, torch && { backgroundColor: colors.cyan }]}>
            <Icon name="bolt" color={torch ? colors.onAccent : '#fff'} />
          </Pressable>
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
  round: { width: 46, height: 46, borderRadius: 23, alignItems: 'center', justifyContent: 'center', backgroundColor: 'rgba(15,31,51,.8)', borderWidth: 1, borderColor: 'rgba(255,255,255,.15)' },
});
