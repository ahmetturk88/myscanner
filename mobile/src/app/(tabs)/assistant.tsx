import { useRef, useState } from 'react';
import { KeyboardAvoidingView, Platform, Pressable, ScrollView, Text, TextInput, View, type ScrollViewInstance } from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';

import { Bubble } from '@/components/ai';
import { Button, ErrorText, Muted, Title } from '@/components/ui';
import { plain, stream } from '@/lib/api';
import { colors, radius } from '@/lib/theme';

type Message = { role: 'user' | 'assistant'; text: string };
const SUGGESTIONS = [
  'I got a message asking me to verify my bank account. Is it a scam?',
  'How do I secure my email account?',
  'I clicked a suspicious link. What should I do now?',
];

export default function Assistant() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const scroller = useRef<ScrollViewInstance>(null);

  async function send(text = input) {
    const message = text.trim();
    if (!message || busy) return;
    const history = messages.slice(-20);
    setInput(''); setBusy(true); setError(null);
    setMessages((m) => [...m, { role: 'user', text: message }, { role: 'assistant', text: '' }]);
    const update = (answer: string) => setMessages((m) => [...m.slice(0, -1), { role: 'assistant', text: answer }]);
    try {
      const final = await stream('/ai/assistant', { message, history }, (t) => update(plain(t)));
      update(final.answer);
    } catch (e: any) {
      setMessages((m) => m.slice(0, -2));
      setInput(message);
      setError(e.message);
    } finally { setBusy(false); }
  }

  return (
    <SafeAreaView style={{ flex: 1, backgroundColor: colors.bg }} edges={['top']}>
      <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : 'height'}>
        <ScrollView ref={scroller} contentContainerStyle={{ padding: 16, gap: 10, flexGrow: 1 }} keyboardShouldPersistTaps="handled"
          onContentSizeChange={() => scroller.current?.scrollToEnd({ animated: true })}>
          <Title kicker="✦ AI ASSISTANT" sub="Ask anything about links, messages, scams and account security, in any language.">Your security assistant</Title>
          {!messages.length && SUGGESTIONS.map((s) => (
            <Pressable key={s} accessibilityRole="button" onPress={() => send(s)}
              style={{ borderWidth: 1, borderColor: colors.line, backgroundColor: colors.surface, borderRadius: radius.md, padding: 12 }}>
              <Text style={{ color: colors.text, fontSize: 14, lineHeight: 20 }}>{s}</Text>
            </Pressable>
          ))}
          {messages.map((m, i) => <Bubble key={i} role={m.role} text={m.text} />)}
          <ErrorText>{error}</ErrorText>
        </ScrollView>
        <View style={{ padding: 12, paddingBottom: 16, gap: 8, borderTopWidth: 1, borderTopColor: colors.line, backgroundColor: colors.bg }}>
          <TextInput value={input} onChangeText={setInput} placeholder="Ask about online safety…" placeholderTextColor={colors.faint}
            multiline maxLength={1000} style={{ minHeight: 48, maxHeight: 120, borderRadius: radius.md, borderWidth: 1, borderColor: colors.line,
              backgroundColor: '#070f1c', color: colors.text, padding: 12, fontSize: 16 }} />
          <View style={{ flexDirection: 'row', gap: 8 }}>
            <View style={{ flex: 1 }}><Button label="Send" onPress={() => send()} busy={busy} disabled={!input.trim()} /></View>
            {messages.length ? <Button label="New" kind="secondary" onPress={() => { setMessages([]); setError(null); }} disabled={busy} /> : null}
          </View>
          <Muted>AI can make mistakes and cannot scan anything by itself. Each answer uses 1 of your 10 daily AI requests.</Muted>
        </View>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}
