import { useState } from 'react';
import { View } from 'react-native';
import Animated from 'react-native-reanimated';

import { Icon } from '@/components/icon';
import { enter } from '@/components/motion';
import { Screen } from '@/components/screen';
import { Body, Button, ErrorText, Field, Muted } from '@/components/ui';
import { api } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { colors } from '@/lib/theme';

export default function DeleteAccount() {
  const { user, forget } = useAuth();
  const [typed, setTyped] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function remove() {
    setBusy(true); setError(null);
    try {
      await api.deleteAccount(typed);
      await forget();
    } catch (e: any) {
      setError(e.message);
      setBusy(false);
    }
  }

  return (
    <Screen back title="Delete account" eyebrow="Account" badge={
      <View style={{ width: 58, height: 58, borderRadius: 20, alignItems: 'center', justifyContent: 'center', marginBottom: 10,
        backgroundColor: 'rgba(251,113,133,.1)', borderWidth: 1, borderColor: 'rgba(251,113,133,.35)' }}>
        <Icon name="trash" size={26} color={colors.red} />
      </View>}>
      <Animated.View entering={enter(1)} style={{ gap: 10, padding: 18, borderRadius: 22, borderWidth: 1, borderColor: 'rgba(251,113,133,.3)', backgroundColor: 'rgba(40,14,24,.35)' }}>
        <Body>This permanently deletes your MyScanner account and everything stored with it: your reports, scan history, AI conversations and sign-ins on every device. It cannot be undone.</Body>
        <Muted>Backups roll over on their own, so copies of deleted data disappear from them within 30 days.</Muted>
      </Animated.View>
      <Animated.View entering={enter(2)} style={{ gap: 14 }}>
        <Field label={`Type your email to confirm: ${user?.email ?? ''}`} value={typed} onChangeText={setTyped}
          autoCapitalize="none" keyboardType="email-address" autoCorrect={false} />
        <ErrorText>{error}</ErrorText>
        <Button label="Delete my account permanently" icon="trash" kind="danger" onPress={remove} busy={busy}
          disabled={typed.trim().toLowerCase() !== (user?.email ?? '').toLowerCase()} />
      </Animated.View>
    </Screen>
  );
}
