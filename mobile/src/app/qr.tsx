import { CameraView, useCameraPermissions } from 'expo-camera';
import * as Haptics from 'expo-haptics';
import { router } from 'expo-router';
import { useRef, useState } from 'react';
import { Text, View } from 'react-native';

import { Body, Button, Card, ErrorText, Muted, Screen } from '@/components/ui';
import { api } from '@/lib/api';
import { colors, radius } from '@/lib/theme';

export default function QrScanner() {
  const [permission, requestPermission] = useCameraPermissions();
  const [code, setCode] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const locked = useRef(false);

  if (!permission) return null;
  if (!permission.granted) {
    return (
      <Screen>
        <Card>
          <Body>MyScanner needs the camera to read QR codes. Nothing is recorded or uploaded except the text inside the code.</Body>
          <Button label="Allow camera" onPress={requestPermission} />
        </Card>
      </Screen>
    );
  }

  const isLink = !!code && /^https?:\/\//i.test(code.trim());

  async function scanLink() {
    setBusy(true); setError(null);
    try {
      const queued: any = await api.tool('url', { url: code!.trim() });
      router.replace({ pathname: '/scan/[id]', params: { id: String(queued.scan_id) } });
    } catch (e: any) {
      setError(e.message);
      setBusy(false);
    }
  }

  if (code) {
    return (
      <Screen>
        <Card>
          <Muted>The QR code contains:</Muted>
          <Text selectable style={{ color: colors.text, fontSize: 16, lineHeight: 24 }}>{code}</Text>
          {isLink ? <Muted>Do not open it yet. Check it first.</Muted> : <Muted>This is not a web link, so there is nothing to scan online.</Muted>}
          <ErrorText>{error}</ErrorText>
          {isLink ? <Button label="Check this link" onPress={scanLink} busy={busy} /> : null}
          <Button label="Scan another code" kind="secondary" onPress={() => { locked.current = false; setCode(null); setError(null); }} />
        </Card>
      </Screen>
    );
  }

  return (
    <View style={{ flex: 1, backgroundColor: colors.bg }}>
      <CameraView style={{ flex: 1 }} facing="back" barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
        onBarcodeScanned={({ data }) => {
          if (locked.current || !data) return;
          locked.current = true;
          Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success).catch(() => {});
          setCode(data);
        }} />
      <View pointerEvents="none" style={{ position: 'absolute', top: '25%', alignSelf: 'center', width: 240, height: 240,
        borderWidth: 3, borderColor: colors.cyan, borderRadius: radius.lg }} />
      <Text style={{ position: 'absolute', bottom: 60, alignSelf: 'center', color: colors.text, fontSize: 16, fontWeight: '600' }}>
        Point the camera at a QR code
      </Text>
    </View>
  );
}
