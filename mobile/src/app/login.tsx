import { LinearGradient } from 'expo-linear-gradient';
import * as WebBrowser from 'expo-web-browser';
import { useEffect, useState } from 'react';
import { KeyboardAvoidingView, Platform, Pressable, ScrollView, StyleSheet, Text, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

import { BrandMark } from '@/components/brand';
import { Appear } from '@/components/motion';
import { Backdrop, Button, ErrorText, Field } from '@/components/ui';
import { api, SITE } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { colors, fonts } from '@/lib/theme';

/** The website's sign-in page: the brand panel, then the sign-in form. */
export default function Login() {
  const { signIn, signInWith } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [providers, setProviders] = useState<string[]>([]);
  const [providerBusy, setProviderBusy] = useState<string | null>(null);
  useEffect(() => { api.providers().then((d) => setProviders(d.providers)).catch(() => {}); }, []);

  async function submit() {
    if (!email.trim() || !password) return;
    setBusy(true); setError(null);
    try { await signIn(email, password); } catch (e: any) { setError(e.message); } finally { setBusy(false); }
  }

  async function withProvider(provider: string) {
    setProviderBusy(provider); setError(null);
    try { await signInWith(provider); } catch (e: any) { setError(e.message); } finally { setProviderBusy(null); }
  }

  const open = (path: string) => WebBrowser.openBrowserAsync(SITE + path);

  return (
    <Backdrop>
      <SafeAreaView style={{ flex: 1 }}>
        <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
          <ScrollView contentContainerStyle={{ padding: 14, gap: 16, paddingBottom: 40 }} keyboardShouldPersistTaps="handled">
            <Appear>
              <LinearGradient colors={['#123a5c', '#0d1a2e', '#1a1440']} locations={[0, 0.55, 1]} start={{ x: 0, y: 0 }} end={{ x: 1, y: 1 }} style={s.side}>
                <View style={{ flexDirection: 'row', alignItems: 'center', gap: 10 }}>
                  <BrandMark size={40} />
                  <Text style={{ color: colors.text, fontSize: 22, fontFamily: fonts.extrabold, letterSpacing: -0.6 }}>My<Text style={{ color: '#00c8f2' }}>Scanner</Text></Text>
                </View>
                <View style={s.pill}>
                  <View style={{ width: 7, height: 7, borderRadius: 4, backgroundColor: colors.teal }} />
                  <Text style={{ color: '#9eeaff', fontSize: 11.5, letterSpacing: 2, fontFamily: fonts.monoBold }}>SECURITY WORKSPACE</Text>
                </View>
                <Text style={{ color: colors.text, fontSize: 32, lineHeight: 35, fontFamily: fonts.bold, letterSpacing: -1.2 }}>
                  Evidence <Text style={{ color: colors.cyan }}>before</Text>{'\n'}trust.
                </Text>
                <Text style={{ color: colors.soft, fontSize: 15.5, lineHeight: 25, fontFamily: fonts.regular }}>
                  Check links, files, emails and domains, and see exactly what was found and what is still unknown.
                </Text>
              </LinearGradient>
            </Appear>
            <Appear delay={100}>
              <View style={s.form}>
                <Text style={{ color: colors.text, fontSize: 27, fontFamily: fonts.bold, letterSpacing: -0.8 }}>Sign in to MyScanner</Text>
                <Text style={{ color: colors.soft, fontSize: 15, lineHeight: 23, fontFamily: fonts.regular, marginTop: -6 }}>Your reports, workspace and history are waiting.</Text>
                <Field label="Email" icon="mail" value={email} onChangeText={setEmail} autoCapitalize="none" autoComplete="email"
                  keyboardType="email-address" textContentType="emailAddress" placeholder="you@example.com" />
                <Field label="Password" icon="lock" value={password} onChangeText={setPassword} secureTextEntry autoComplete="current-password"
                  textContentType="password" placeholder="Your password" onSubmitEditing={submit} returnKeyType="go" />
                <Pressable onPress={() => open('/forgot-password')} style={{ alignSelf: 'flex-end' }} hitSlop={8}>
                  <Text style={{ color: colors.cyan, fontSize: 14.5, fontFamily: fonts.bold }}>Forgot password?</Text>
                </Pressable>
                <ErrorText>{error}</ErrorText>
                <Button label="Sign in" arrow="→" onPress={submit} busy={busy} disabled={!email.trim() || !password} />
                {providers.length ? (
                  <>
                    <View style={{ flexDirection: 'row', alignItems: 'center', gap: 10 }}>
                      <View style={{ flex: 1, height: 1, backgroundColor: colors.line }} />
                      <Text style={{ color: colors.faint, fontSize: 13, fontFamily: fonts.regular }}>or continue with</Text>
                      <View style={{ flex: 1, height: 1, backgroundColor: colors.line }} />
                    </View>
                    {providers.map((p) => (
                      <Button key={p} kind="secondary" label={p === 'github' ? 'GitHub' : 'Google'}
                        onPress={() => withProvider(p)} busy={providerBusy === p} disabled={!!providerBusy} />
                    ))}
                  </>
                ) : null}
                <Text style={{ color: colors.soft, fontSize: 14.5, textAlign: 'center', fontFamily: fonts.regular }}>
                  New to MyScanner? <Text onPress={() => open('/register')} style={{ color: colors.cyan, fontFamily: fonts.bold }}>Create a free account</Text>
                </Text>
              </View>
            </Appear>
          </ScrollView>
        </KeyboardAvoidingView>
      </SafeAreaView>
    </Backdrop>
  );
}

const s = StyleSheet.create({
  side: { borderRadius: 22, borderWidth: 1, borderColor: 'rgba(119,220,255,.18)', padding: 22, gap: 18 },
  pill: { flexDirection: 'row', alignItems: 'center', gap: 8, alignSelf: 'flex-start', paddingVertical: 6, paddingHorizontal: 12, borderRadius: 999, borderWidth: 1, borderColor: 'rgba(119,220,255,.35)', backgroundColor: 'rgba(8,19,33,.6)' },
  form: { borderRadius: 22, borderWidth: 1, borderColor: colors.line, backgroundColor: '#0d1726', padding: 20, gap: 16 },
});
