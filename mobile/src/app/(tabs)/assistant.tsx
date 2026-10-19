import { LinearGradient } from 'expo-linear-gradient';
import { useRef, useState } from 'react';
import { KeyboardAvoidingView, ScrollView, StyleSheet, Text, TextInput, View } from 'react-native';
import Animated, { FadeInUp } from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { Bubble } from '@/components/ai';
import { BrandMark } from '@/components/brand';
import { Icon } from '@/components/icon';
import { Ambient, enter, PressableScale, Pulse, Spin } from '@/components/motion';
import { TAB_SPACE, useKeyboardVisible } from '@/components/screen';
import { ErrorText, styles as ui } from '@/components/ui';
import { plain, stream } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { startUrlScan } from '@/lib/scan';
import { colors, fonts, gradients } from '@/lib/theme';
import { findLink } from '@/lib/tools';

type Message = { role: 'user' | 'assistant'; text: string; link?: string | null };
const SUGGESTIONS: [string, string][] = [
  ['alert', 'I got a message asking me to verify my bank account. Is it a scam?'],
  ['lock', 'How do I secure my email account?'],
  ['link', 'I clicked a suspicious link. What should I do now?'],
  ['qr', 'Is it safe to scan a QR code on a parking meter?'],
];

/** The assistant's animated mark: the brand inside a turning gradient ring. */
function Orb({ size }: { size: number }) {
  return (
    <Pulse size={size} color="rgba(167,139,250,.6)">
      <View style={{ width: size, height: size, alignItems: 'center', justifyContent: 'center' }}>
        <View style={StyleSheet.absoluteFill}>
          <Spin duration={4000}><LinearGradient colors={['#38bdf8', '#a78bfa', '#5eead4']} style={{ width: size, height: size, borderRadius: size / 2 }} /></Spin>
        </View>
        <View style={{ width: size - 6, height: size - 6, borderRadius: size, backgroundColor: '#0b1422', alignItems: 'center', justifyContent: 'center' }}>
          <BrandMark size={size * 0.5} />
        </View>
      </View>
    </Pulse>
  );
}

export default function Assistant() {
  const { user, refresh } = useAuth();
  const insets = useSafeAreaInsets();
  const keyboard = useKeyboardVisible();
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const scroller = useRef<ScrollView>(null);
  const ai = user?.allowance.find((a) => a.service === 'ai_assistant');

  async function send(text = input) {
    const message = text.trim();
    if (!message || busy) return;
    const history = messages.slice(-20).map(({ role, text: t }) => ({ role, text: t }));
    setInput(''); setBusy(true); setError(null);
    setMessages((m) => [...m, { role: 'user', text: message, link: findLink(message) }, { role: 'assistant', text: '' }]);
    const update = (answer: string) => setMessages((m) => [...m.slice(0, -1), { role: 'assistant', text: answer }]);
    try {
      const final = await stream('/ai/assistant', { message, history }, (t) => update(plain(t)));
      update(final.answer);
      refresh().catch(() => {});
    } catch (e: any) {
      setMessages((m) => m.slice(0, -2));
      setInput(message);
      setError(e.message);
    } finally { setBusy(false); }
  }

  async function scanLink(link: string) {
    setError(null);
    try { await startUrlScan(link); } catch (e: any) { setError(e.message); }
  }

  return (
    <View style={{ flex: 1, backgroundColor: colors.bg }}>
      <Ambient />
      <KeyboardAvoidingView style={{ flex: 1, paddingTop: insets.top }} behavior="padding">
        <View style={s.header}>
          <Orb size={40} />
          <View style={{ gap: 1 }}>
            <Text style={{ color: colors.text, fontSize: 17, fontFamily: fonts.bold }}>MyScanner AI</Text>
            <Text style={{ color: busy ? colors.cyan : colors.green, fontSize: 12, fontFamily: fonts.medium }}>{busy ? 'Thinking…' : 'Online'}</Text>
          </View>
          <View style={{ marginLeft: 'auto', flexDirection: 'row', alignItems: 'center', gap: 8 }}>
            {ai ? <View style={s.quota}><Text style={{ color: colors.cyan, fontSize: 11.5, fontFamily: fonts.monoBold }}>{ai.limit === null ? '∞' : `${ai.remaining} left`}</Text></View> : null}
            {messages.length ? (
              <PressableScale accessibilityLabel="New conversation" disabled={busy} onPress={() => { setMessages([]); setError(null); }} style={s.round}>
                <Icon name="refresh" size={17} color={colors.soft} />
              </PressableScale>
            ) : null}
          </View>
        </View>
        <ScrollView ref={scroller} contentContainerStyle={{ padding: 18, gap: 12, flexGrow: 1 }} keyboardShouldPersistTaps="handled"
          onContentSizeChange={() => scroller.current?.scrollToEnd({ animated: true })} showsVerticalScrollIndicator={false}>
          {!messages.length ? (
            <View style={{ gap: 12, flex: 1, justifyContent: 'center' }}>
              <Animated.View entering={enter(0)} style={{ alignItems: 'center', gap: 16, marginBottom: 10 }}>
                <Orb size={86} />
                <Text style={{ color: colors.text, fontSize: 26, fontFamily: fonts.bold, letterSpacing: -0.8, textAlign: 'center' }}>
                  How can I help you{'\n'}stay <Text style={{ color: colors.cyan }}>safe?</Text>
                </Text>
                <Text style={[ui.muted, { textAlign: 'center' }]}>Ask about links, messages and scams. Paste a link and I can scan it.</Text>
              </Animated.View>
              {SUGGESTIONS.map(([icon, text], i) => (
                <Animated.View key={text} entering={enter(i + 1)}>
                  <PressableScale scale={0.98} onPress={() => send(text)} style={s.suggestion}>
                    <Icon name={icon as any} size={17} color={colors.cyan} />
                    <Text style={{ flex: 1, color: colors.soft, fontSize: 14.5, lineHeight: 21, writingDirection: 'auto', fontFamily: fonts.regular }}>{text}</Text>
                  </PressableScale>
                </Animated.View>
              ))}
            </View>
          ) : null}
          {messages.map((m, i) => (
            <Animated.View key={i} entering={FadeInUp.duration(320)} style={{ gap: 8 }}>
              <Bubble role={m.role} text={m.text} />
              {m.link ? (
                <PressableScale onPress={() => scanLink(m.link!)} style={s.scanLink}>
                  <Icon name="shield" size={16} color={colors.cyan} />
                  <Text style={{ color: '#a5f3fc', fontFamily: fonts.bold, fontSize: 13.5 }}>Scan this link</Text>
                </PressableScale>
              ) : null}
            </Animated.View>
          ))}
          <ErrorText>{error}</ErrorText>
        </ScrollView>
        <View style={{ paddingHorizontal: 16, paddingTop: 6, paddingBottom: keyboard ? 10 : TAB_SPACE + insets.bottom - 8 }}>
          <View style={[ui.inputWrap, s.composer]}>
            <TextInput value={input} onChangeText={setInput} placeholder="Ask anything…" placeholderTextColor={colors.faint}
              multiline maxLength={1000} style={[ui.input, { maxHeight: 120 }]} />
            <PressableScale accessibilityLabel="Send" scale={0.9} onPress={() => send()} disabled={!input.trim() || busy}
              style={{ opacity: !input.trim() || busy ? 0.45 : 1 }}>
              <LinearGradient colors={gradients.accent} style={s.send}><Icon name="send" size={18} color={colors.onAccent} /></LinearGradient>
            </PressableScale>
          </View>
        </View>
      </KeyboardAvoidingView>
    </View>
  );
}

const s = StyleSheet.create({
  header: { flexDirection: 'row', alignItems: 'center', gap: 12, paddingHorizontal: 18, paddingVertical: 10, borderBottomWidth: 1, borderBottomColor: 'rgba(145,188,220,.1)' },
  quota: { borderWidth: 1, borderColor: colors.line2, borderRadius: 999, paddingVertical: 5, paddingHorizontal: 10 },
  round: { width: 38, height: 38, borderRadius: 19, alignItems: 'center', justifyContent: 'center', backgroundColor: 'rgba(17,35,56,.85)', borderWidth: 1, borderColor: '#2b4560' },
  suggestion: { flexDirection: 'row', alignItems: 'center', gap: 12, borderWidth: 1, borderColor: '#24425e', backgroundColor: 'rgba(16,35,58,.75)', borderRadius: 16, padding: 14 },
  scanLink: { alignSelf: 'flex-end', flexDirection: 'row', alignItems: 'center', gap: 8, paddingVertical: 9, paddingHorizontal: 12, borderRadius: 14, backgroundColor: '#0b2232', borderWidth: 1, borderColor: 'rgba(119,220,255,.35)' },
  composer: { alignItems: 'flex-end', paddingVertical: 6, paddingRight: 6, borderRadius: 22, backgroundColor: '#0c1726' },
  send: { width: 42, height: 42, borderRadius: 16, alignItems: 'center', justifyContent: 'center' },
});
