import { LinearGradient } from 'expo-linear-gradient';
import { useRef, useState } from 'react';
import { KeyboardAvoidingView, Platform, Pressable, ScrollView, Text, TextInput, View } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

import { Bubble } from '@/components/ai';
import { TAB_BAR_SPACE } from '@/components/app-tabs';
import { Icon } from '@/components/icon';
import { Appear } from '@/components/motion';
import { Backdrop, ErrorText, styles as ui } from '@/components/ui';
import { plain, stream } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { startUrlScan } from '@/lib/scan';
import { colors, gradients } from '@/lib/theme';
import { findLink } from '@/lib/tools';

type Message = { role: 'user' | 'assistant'; text: string; link?: string | null };
const SUGGESTIONS = [
  'I got a message asking me to verify my bank account. Is it a scam?',
  'How do I secure my email account?',
  'I clicked a suspicious link. What should I do now?',
  'وصلتني رسالة فيها رابط غريب، شو لازم أعمل؟',
];

export default function Assistant() {
  const { user, refresh } = useAuth();
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
    <Backdrop>
      <SafeAreaView style={{ flex: 1 }} edges={['top']}>
        <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
          <View style={{ flexDirection: 'row', alignItems: 'center', paddingHorizontal: 16, paddingTop: 6, paddingBottom: 10 }}>
            <Text style={{ color: colors.text, fontSize: 21, fontWeight: '800' }}>✦ Assistant</Text>
            {ai ? (
              <View style={{ marginLeft: 'auto', borderWidth: 1, borderColor: colors.line2, borderRadius: 999, paddingVertical: 5, paddingHorizontal: 11 }}>
                <Text style={{ color: colors.cyanSoft, fontSize: 12, fontWeight: '700' }}>{ai.limit === null ? 'Unlimited' : `${ai.remaining} left today`}</Text>
              </View>
            ) : null}
            {messages.length ? (
              <Pressable accessibilityRole="button" accessibilityLabel="New conversation" disabled={busy} hitSlop={8}
                onPress={() => { setMessages([]); setError(null); }} style={[ui.iconButton, { marginLeft: 10 }]}>
                <Icon name="refresh" size={18} color={colors.soft} />
              </Pressable>
            ) : null}
          </View>
          <ScrollView ref={scroller} contentContainerStyle={{ padding: 16, paddingTop: 4, gap: 12, flexGrow: 1 }} keyboardShouldPersistTaps="handled"
            onContentSizeChange={() => scroller.current?.scrollToEnd({ animated: true })} showsVerticalScrollIndicator={false}>
            {!messages.length ? (
              <Appear>
                <View style={{ gap: 10 }}>
                  <Text style={{ color: colors.text, fontSize: 26, fontWeight: '800', letterSpacing: -0.5 }}>How can I help you stay safe?</Text>
                  <Text style={ui.muted}>Ask about links, messages, scams and account security, in any language. Paste a link and I can scan it for you.</Text>
                  {SUGGESTIONS.map((s) => (
                    <Pressable key={s} accessibilityRole="button" onPress={() => send(s)}
                      style={({ pressed }) => ({ borderWidth: 1, borderColor: colors.line, backgroundColor: pressed ? colors.surface2 : colors.surface, borderRadius: 16, padding: 14 })}>
                      <Text style={{ color: colors.soft, fontSize: 14.5, lineHeight: 21, writingDirection: 'auto' }}>{s}</Text>
                    </Pressable>
                  ))}
                </View>
              </Appear>
            ) : null}
            {messages.map((m, i) => (
              <View key={i} style={{ gap: 8 }}>
                <Bubble role={m.role} text={m.text} />
                {m.link ? (
                  <Pressable accessibilityRole="button" onPress={() => scanLink(m.link!)}
                    style={{ alignSelf: 'flex-end', flexDirection: 'row', alignItems: 'center', gap: 8, paddingVertical: 9, paddingHorizontal: 12,
                      borderRadius: 14, backgroundColor: '#0b2232', borderWidth: 1, borderColor: colors.cyan + '55' }}>
                    <Icon name="shield" size={16} color={colors.cyanSoft} />
                    <Text style={{ color: '#a5f3fc', fontWeight: '700', fontSize: 13.5 }}>Scan this link</Text>
                  </Pressable>
                ) : null}
              </View>
            ))}
            <ErrorText>{error}</ErrorText>
          </ScrollView>
          <View style={{ paddingHorizontal: 16, paddingTop: 8, paddingBottom: TAB_BAR_SPACE - 6 }}>
            <View style={[ui.inputWrap, { paddingRight: 6, alignItems: 'flex-end', paddingVertical: 6 }]}>
              <TextInput value={input} onChangeText={setInput} placeholder="Ask anything…" placeholderTextColor={colors.faint}
                multiline maxLength={1000} style={[ui.input, { maxHeight: 120 }]} />
              <Pressable accessibilityRole="button" accessibilityLabel="Send" onPress={() => send()} disabled={!input.trim() || busy}
                style={{ opacity: !input.trim() || busy ? 0.5 : 1 }}>
                <LinearGradient colors={gradients.accent} style={{ width: 42, height: 42, borderRadius: 13, alignItems: 'center', justifyContent: 'center' }}>
                  <Icon name="send" size={19} color={colors.onAccent} />
                </LinearGradient>
              </Pressable>
            </View>
          </View>
        </KeyboardAvoidingView>
      </SafeAreaView>
    </Backdrop>
  );
}
