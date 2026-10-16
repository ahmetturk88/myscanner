import { LinearGradient } from 'expo-linear-gradient';
import * as WebBrowser from 'expo-web-browser';
import { useEffect, useState } from 'react';
import { KeyboardAvoidingView, Platform, Pressable, Text, View } from 'react-native';

import { BrandMark } from '@/components/brand';
import { Appear } from '@/components/motion';
import { Button, ErrorText, Field, Muted, Screen } from '@/components/ui';
import { api, SITE } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { colors } from '@/lib/theme';

export default function Login() {
  const { signIn, signInWith } = useAuth();
  const [providers, setProviders] = useState<string[]>([]);
  const [providerBusy, setProviderBusy] = useState<string | null>(null);
  useEffect(() => { api.providers().then((d) => setProviders(d.providers)).catch(() => {}); }, []);

  async function withProvider(provider: string) {
    setProviderBusy(provider); setError(null);
    try {
      await signInWith(provider);
    } catch (e: any) {
      setError(e.message);
    } finally { setProviderBusy(null); }
  }
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    if (!email.trim() || !password) return;
    setBusy(true); setError(null);
    try {
      await signIn(email, password);
    } catch (e: any) {
      setError(e.message);
    } finally { setBusy(false); }
  }

  const link = (path: string, label: string) => (
    <Pressable accessibilityRole="link" onPress={() => WebBrowser.openBrowserAsync(SITE + path)} hitSlop={8}>
      <Text style={{ color: colors.cyanSoft, fontSize: 15, fontWeight: '700' }}>{label}</Text>
    </Pressable>
  );

  return (
    <KeyboardAvoidingView style={{ flex: 1, backgroundColor: colors.bg }} behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
      <Screen>
        <Appear>
          <View style={{ alignItems: 'center', gap: 12, marginTop: 36, marginBottom: 8 }}>
            <View style={{ alignItems: 'center', justifyContent: 'center' }}>
              <LinearGradient colors={['rgba(34,211,238,.25)', 'rgba(129,140,248,0)']} style={{ position: 'absolute', width: 170, height: 170, borderRadius: 85 }} />
              <BrandMark size={96} />
            </View>
            <Text style={{ color: colors.text, fontSize: 32, fontWeight: '800', letterSpacing: -0.6 }}>My<Text style={{ color: colors.cyan }}>Scanner</Text></Text>
            <Text style={{ color: colors.faint, fontSize: 12, letterSpacing: 3, fontWeight: '700' }}>EVIDENCE BEFORE TRUST</Text>
            <Muted center>Check links, emails, files and websites before you trust them.</Muted>
          </View>
        </Appear>
        <Appear delay={120}>
          <View style={{ gap: 14 }}>
            <Field label="Email" icon="mail" value={email} onChangeText={setEmail} autoCapitalize="none" autoComplete="email"
              keyboardType="email-address" textContentType="emailAddress" placeholder="name@example.com" />
            <Field label="Password" icon="lock" value={password} onChangeText={setPassword} secureTextEntry autoComplete="current-password"
              textContentType="password" placeholder="Your password" onSubmitEditing={submit} returnKeyType="go" />
            <ErrorText>{error}</ErrorText>
            <Button label="Sign in" onPress={submit} busy={busy} disabled={!email.trim() || !password} />
            {providers.length ? (
              <View style={{ gap: 10 }}>
                <View style={{ flexDirection: 'row', alignItems: 'center', gap: 10, marginVertical: 4 }}>
                  <View style={{ flex: 1, height: 1, backgroundColor: colors.line }} />
                  <Text style={{ color: colors.faint, fontSize: 13 }}>or</Text>
                  <View style={{ flex: 1, height: 1, backgroundColor: colors.line }} />
                </View>
                {providers.map((p) => (
                  <Button key={p} kind="secondary" label={`Continue with ${p === 'github' ? 'GitHub' : 'Google'}`}
                    onPress={() => withProvider(p)} busy={providerBusy === p} disabled={!!providerBusy} />
                ))}
              </View>
            ) : null}
            <View style={{ gap: 14, alignItems: 'center', marginTop: 6 }}>
              {link('/register', 'Create a free account')}
              {link('/forgot-password', 'Forgot your password?')}
            </View>
          </View>
        </Appear>
      </Screen>
    </KeyboardAvoidingView>
  );
}
