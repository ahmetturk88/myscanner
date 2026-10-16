import { Image } from 'expo-image';
import * as WebBrowser from 'expo-web-browser';
import { useState } from 'react';
import { KeyboardAvoidingView, Platform, Pressable, Text, View } from 'react-native';

import { Button, ErrorText, Field, Muted, Screen } from '@/components/ui';
import { SITE } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { colors } from '@/lib/theme';

export default function Login() {
  const { signIn } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setBusy(true); setError(null);
    try {
      await signIn(email, password);
    } catch (e: any) {
      setError(e.message);
    } finally { setBusy(false); }
  }

  const link = (path: string, label: string) => (
    <Pressable accessibilityRole="link" onPress={() => WebBrowser.openBrowserAsync(SITE + path)} hitSlop={8}>
      <Text style={{ color: colors.cyan, fontSize: 15, fontWeight: '600' }}>{label}</Text>
    </Pressable>
  );

  return (
    <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
      <Screen>
        <View style={{ alignItems: 'center', gap: 12, marginTop: 40, marginBottom: 12 }}>
          <Image source={require('@/assets/images/splash-icon.png')} style={{ width: 96, height: 96 }} accessibilityIgnoresInvertColors />
          <Text style={{ color: colors.text, fontSize: 30, fontWeight: '800' }}>My<Text style={{ color: colors.cyan }}>Scanner</Text></Text>
          <Muted>Check links, emails and websites before you trust them.</Muted>
        </View>
        <Field label="Email" value={email} onChangeText={setEmail} autoCapitalize="none" autoComplete="email"
          keyboardType="email-address" textContentType="emailAddress" placeholder="name@example.com" />
        <Field label="Password" value={password} onChangeText={setPassword} secureTextEntry autoComplete="current-password"
          textContentType="password" placeholder="Your password" onSubmitEditing={submit} returnKeyType="go" />
        <ErrorText>{error}</ErrorText>
        <Button label="Sign in" onPress={submit} busy={busy} disabled={!email.trim() || !password} />
        <View style={{ gap: 14, alignItems: 'center', marginTop: 8 }}>
          {link('/register', 'Create a free account')}
          {link('/forgot-password', 'Forgot your password?')}
        </View>
        <Muted>{'Signed up with Google or GitHub? Use "Forgot your password?" once to set a password, then sign in here. Google sign-in inside the app is coming soon.'}</Muted>
      </Screen>
    </KeyboardAvoidingView>
  );
}
