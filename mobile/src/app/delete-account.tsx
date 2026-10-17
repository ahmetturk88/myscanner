import { useState } from 'react';

import { Page } from '@/components/site';
import { Body, Button, Card, ErrorText, Eyebrow, Field, Hero, Muted } from '@/components/ui';
import { api } from '@/lib/api';
import { useAuth } from '@/lib/auth';

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
    <Page footer={false} fab={false}>
      <Eyebrow>Account</Eyebrow>
      <Hero title="Delete your account" size={30} />
      <Card>
        <Body>This permanently deletes your MyScanner account and everything stored with it: your reports, scan history, AI conversations and sign-ins on every device. It cannot be undone.</Body>
        <Muted>Backups roll over on their own, so copies of deleted data disappear from them within 30 days.</Muted>
      </Card>
      <Field label={`Type your account email to confirm: ${user?.email ?? ''}`} value={typed} onChangeText={setTyped}
        autoCapitalize="none" keyboardType="email-address" autoCorrect={false} />
      <ErrorText>{error}</ErrorText>
      <Button label="Delete my account permanently" icon="trash" kind="danger" onPress={remove} busy={busy}
        disabled={typed.trim().toLowerCase() !== (user?.email ?? '').toLowerCase()} />
    </Page>
  );
}
