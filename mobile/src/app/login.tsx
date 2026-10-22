import * as WebBrowser from 'expo-web-browser';
import { useEffect, useState } from 'react';
import { KeyboardAvoidingView, Pressable, ScrollView, StyleSheet, Text, View } from 'react-native';
import Animated from 'react-native-reanimated';
import { SafeAreaView } from 'react-native-safe-area-context';

import { BrandMark } from '@/components/brand';
import { enter, Pulse } from '@/components/motion';
import { NetworkBackground } from '@/components/network-background';
import { Button, ErrorText, Field } from '@/components/ui';
import { api, SITE } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { t } from '@/lib/i18n';
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
    <View style={{ flex: 1, backgroundColor: colors.bg }}>
      <NetworkBackground />
      <SafeAreaView style={{ flex: 1 }}>
        <KeyboardAvoidingView style={{ flex: 1 }} behavior="padding">
          <ScrollView contentContainerStyle={{ padding: 20, gap: 22, paddingBottom: 40, flexGrow: 1, justifyContent: 'center' }} keyboardShouldPersistTaps="handled">
            <Animated.View entering={enter(0)} style={{ alignItems: 'center', gap: 14 }}>
              <Pulse size={84}>
                <View style={s.mark}><BrandMark size={50} /></View>
              </Pulse>
              <Text style={{ color: colors.text, fontSize: 26, fontFamily: fonts.extrabold, letterSpacing: -0.8 }}>My<Text style={{ color: '#00c8f2' }}>Scanner</Text></Text>
            </Animated.View>
            <Animated.View entering={enter(1)} style={{ gap: 8, alignItems: 'center' }}>
              <Text style={{ color: colors.text, fontSize: 30, lineHeight: 35, fontFamily: fonts.bold, letterSpacing: -1.1, textAlign: 'center' }}>
                {t('Evidence ')}<Text style={{ color: colors.cyan }}>{t('before')}</Text>{t(' trust.')}
              </Text>
              <Text style={{ color: colors.soft, fontSize: 15, lineHeight: 23, fontFamily: fonts.regular, textAlign: 'center', maxWidth: 320 }}>
                {t('Check links, files, emails and domains before you trust them.')}
              </Text>
            </Animated.View>
            <Animated.View entering={enter(2)} style={s.form}>
              <Field label={t('Email')} icon="mail" value={email} onChangeText={setEmail} autoCapitalize="none" autoComplete="email"
                keyboardType="email-address" textContentType="emailAddress" placeholder={t('you@example.com')} />
              <Field label={t('Password')} icon="lock" value={password} onChangeText={setPassword} secureTextEntry autoComplete="current-password"
                textContentType="password" placeholder={t('Your password')} onSubmitEditing={submit} returnKeyType="go" />
              <Pressable onPress={() => open('/forgot-password')} style={{ alignSelf: 'flex-end' }} hitSlop={8}>
                <Text style={{ color: colors.cyan, fontSize: 14, fontFamily: fonts.semibold }}>{t('Forgot password?')}</Text>
              </Pressable>
              <ErrorText>{error}</ErrorText>
              <Button label={t('Sign in')} arrow="→" onPress={submit} busy={busy} disabled={!email.trim() || !password} />
              {providers.length ? (
                <>
                  <View style={{ flexDirection: 'row', alignItems: 'center', gap: 10 }}>
                    <View style={{ flex: 1, height: 1, backgroundColor: colors.line }} />
                    <Text style={{ color: colors.faint, fontSize: 13, fontFamily: fonts.regular }}>{t('or continue with')}</Text>
                    <View style={{ flex: 1, height: 1, backgroundColor: colors.line }} />
                  </View>
                  <View style={{ flexDirection: 'row', gap: 10 }}>
                    {providers.map((p) => (
                      <Button key={p} kind="secondary" flex={1} label={p === 'github' ? 'GitHub' : 'Google'}
                        onPress={() => withProvider(p)} busy={providerBusy === p} disabled={!!providerBusy} />
                    ))}
                  </View>
                </>
              ) : null}
            </Animated.View>
            <Animated.View entering={enter(3)}>
              <Text style={{ color: colors.soft, fontSize: 14.5, textAlign: 'center', fontFamily: fonts.regular }}>
                {t('New to MyScanner?')} <Text onPress={() => open('/register')} style={{ color: colors.cyan, fontFamily: fonts.bold }}>{t('Create a free account')}</Text>
              </Text>
            </Animated.View>
          </ScrollView>
        </KeyboardAvoidingView>
      </SafeAreaView>
    </View>
  );
}

const s = StyleSheet.create({
  mark: { width: 84, height: 84, borderRadius: 28, alignItems: 'center', justifyContent: 'center', backgroundColor: '#0b1a2b', borderWidth: 1, borderColor: 'rgba(119,220,255,.35)' },
  form: { borderRadius: 26, borderWidth: 1, borderColor: colors.line, backgroundColor: 'rgba(13,23,38,.92)', padding: 20, gap: 16 },
});
