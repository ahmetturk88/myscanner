import { router } from 'expo-router';
import { useState } from 'react';
import { Pressable, Text, View } from 'react-native';

import { Button, Card, ErrorText, Field, Muted, Screen, Title } from '@/components/ui';
import { api } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { colors, radius } from '@/lib/theme';
import { TOOLS } from '@/lib/tools';

export default function Home() {
  const { user } = useAuth();
  const [url, setUrl] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function scan() {
    setBusy(true); setError(null);
    try {
      const queued: any = await api.tool('url', { url: url.trim() });
      setUrl('');
      router.push({ pathname: '/scan/[id]', params: { id: String(queued.scan_id) } });
    } catch (e: any) {
      setError(e.message);
    } finally { setBusy(false); }
  }

  return (
    <Screen>
      <Title kicker="MYSCANNER" sub="Paste a link from a message or email and see what is behind it before you open it.">
        {`Hi ${user?.username ?? ''}, what do you want to check?`}
      </Title>
      <Card>
        <Field label="Link to check" value={url} onChangeText={setUrl} placeholder="https://example.com" autoCapitalize="none"
          autoCorrect={false} keyboardType="url" onSubmitEditing={scan} returnKeyType="go" />
        <ErrorText>{error}</ErrorText>
        <Button label="Scan link" onPress={scan} busy={busy} disabled={!url.trim()} />
        <Button label="Scan a QR code with the camera" kind="secondary" onPress={() => router.push('/qr')} />
      </Card>
      <Text style={{ color: colors.text, fontSize: 18, fontWeight: '800', marginTop: 8 }}>More tools</Text>
      <View style={{ flexDirection: 'row', flexWrap: 'wrap', gap: 10 }}>
        {TOOLS.map((tool) => (
          <Pressable key={tool.name} accessibilityRole="button" onPress={() => router.push({ pathname: '/tool/[name]', params: { name: tool.name } })}
            style={({ pressed }) => ({ width: '48%', flexGrow: 1, backgroundColor: pressed ? colors.surface2 : colors.surface,
              borderRadius: radius.md, borderWidth: 1, borderColor: colors.line, padding: 14, gap: 6 })}>
            <Text style={{ color: colors.cyan, fontSize: 20 }}>{tool.icon}</Text>
            <Text style={{ color: colors.text, fontSize: 15, fontWeight: '700' }}>{tool.title}</Text>
            <Muted>{tool.hint}</Muted>
          </Pressable>
        ))}
      </View>
    </Screen>
  );
}
