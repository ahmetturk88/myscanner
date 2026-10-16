import { useRef, useState } from 'react';
import { Text, View } from 'react-native';

import { Button, Card, ErrorText, Field, Muted, styles as ui } from '@/components/ui';
import { api, plain, stream } from '@/lib/api';
import { colors } from '@/lib/theme';

type Explanation = {
  headline: string; summary: string;
  reasons: { point: string; evidence: string }[];
  next_steps: string[]; not_checked: string[]; technical_notes: string[];
};

const LABELS: Record<string, keyof Explanation> = {
  'WHY THIS RESULT': 'reasons', 'WHAT TO DO NOW': 'next_steps', 'NOT CONFIRMED': 'not_checked', 'TECHNICAL NOTES': 'technical_notes',
};
const SECTIONS: [keyof Explanation, string, string][] = [
  ['reasons', 'Why this result', colors.cyan], ['next_steps', 'What to do now', colors.green],
  ['not_checked', 'What was not confirmed', colors.amber], ['technical_notes', 'Technical notes', colors.muted],
];

/** Read the labelled explanation as it streams in (mirrors the server's parser). */
function parse(text: string): Explanation {
  const data: Explanation = { headline: '', summary: '', reasons: [], next_steps: [], not_checked: [], technical_notes: [] };
  let current: keyof Explanation | null = null;
  for (const raw of plain(text).split('\n')) {
    const line = raw.trim();
    const colon = line.indexOf(':');
    const label = colon < 0 ? '' : line.slice(0, colon).trim().toUpperCase();
    const rest = colon < 0 ? '' : line.slice(colon + 1).trim();
    if (label === 'HEADLINE' || label === 'SUMMARY') {
      current = label.toLowerCase() as keyof Explanation;
      (data as any)[current] = rest;
    } else if (LABELS[label] && !rest) {
      current = LABELS[label];
    } else if (current && Array.isArray(data[current]) && line.startsWith('-')) {
      const item = line.replace(/^[-\s]+/, '');
      if (!item) continue;
      if (current === 'reasons') {
        const [point, evidence = ''] = item.split('|');
        data.reasons.push({ point: point.trim(), evidence: evidence.trim() });
      } else (data[current] as string[]).push(item);
    } else if ((current === 'headline' || current === 'summary') && line) {
      (data as any)[current] = `${data[current]} ${line}`.trim();
    }
  }
  return data;
}

function ExplanationView({ data }: { data: Explanation }) {
  return (
    <View style={{ gap: 12 }}>
      {data.headline ? <Text style={{ color: colors.text, fontSize: 18, fontWeight: '700', lineHeight: 26 }}>{data.headline}</Text> : null}
      {data.summary ? <Text style={ui.body}>{data.summary}</Text> : null}
      {SECTIONS.map(([key, title, tint]) => {
        const items = data[key] as any[];
        if (!items.length) return null;
        return (
          <View key={key} style={{ gap: 6, borderTopWidth: 1, borderTopColor: colors.line, paddingTop: 10 }}>
            <Text style={{ color: tint, fontSize: 12, fontWeight: '800', letterSpacing: 1 }}>{title.toUpperCase()}</Text>
            {items.map((item, i) => (
              <Text key={i} style={ui.body}>
                {'•  '}{typeof item === 'string' ? item : item.point}
                {typeof item === 'object' && item.evidence ? <Text style={{ color: colors.faint, fontSize: 13 }}>{`\n    ${item.evidence}`}</Text> : null}
              </Text>
            ))}
          </View>
        );
      })}
    </View>
  );
}

export function Bubble({ role, text }: { role: 'user' | 'assistant'; text: string }) {
  const mine = role === 'user';
  return (
    <View style={{ alignSelf: mine ? 'flex-end' : 'flex-start', maxWidth: '88%', backgroundColor: mine ? '#1d4ed8' : colors.surface2,
      borderRadius: 16, borderWidth: mine ? 0 : 1, borderColor: colors.line, paddingVertical: 10, paddingHorizontal: 14 }}>
      <Text selectable style={{ color: colors.text, fontSize: 15, lineHeight: 23, writingDirection: 'auto' }}>{text || '…'}</Text>
    </View>
  );
}

/** "Explain this report" plus follow-up questions, for any finished report. */
export function AIPanel({ tool, evidence }: { tool: string; evidence: unknown }) {
  const context = useRef<string | null>(null);
  const [explanation, setExplanation] = useState<Explanation | null>(null);
  const [chat, setChat] = useState<{ role: 'user' | 'assistant'; text: string }[]>([]);
  const [question, setQuestion] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function ensureContext() {
    if (!context.current) context.current = (await api.createContext(tool, evidence)).id;
    return context.current;
  }

  async function explain() {
    setBusy(true); setError(null);
    try {
      const id = await ensureContext();
      const final = await stream(`/ai/contexts/${id}/explain`, { language: 'en' }, (text) => setExplanation(parse(text)));
      setExplanation(final.explanation);
    } catch (e: any) {
      setError(e.message);
    } finally { setBusy(false); }
  }

  async function ask() {
    const message = question.trim();
    if (!message || busy) return;
    setQuestion(''); setBusy(true); setError(null);
    setChat((c) => [...c, { role: 'user', text: message }, { role: 'assistant', text: '' }]);
    const update = (text: string) => setChat((c) => [...c.slice(0, -1), { role: 'assistant', text }]);
    try {
      const id = await ensureContext();
      const final = await stream(`/ai/contexts/${id}/chat`, { message }, (text) => update(plain(text)));
      update(final.answer);
    } catch (e: any) {
      setChat((c) => c.slice(0, -2));
      setQuestion(message);
      setError(e.message);
    } finally { setBusy(false); }
  }

  return (
    <Card style={{ borderColor: '#3b5f80' }}>
      <Text style={ui.kicker}>✦ AI ASSISTANT</Text>
      <Text style={{ color: colors.text, fontSize: 19, fontWeight: '800' }}>Understand this report</Text>
      <Muted>A plain-language explanation of the evidence. Ask follow-up questions in any language. Each answer uses 1 of your 10 daily AI requests.</Muted>
      {!explanation ? <Button label="Explain this report" onPress={explain} busy={busy && !chat.length} /> : <ExplanationView data={explanation} />}
      {chat.map((m, i) => <Bubble key={i} role={m.role} text={m.text} />)}
      <Field label="Ask a question about this report" value={question} onChangeText={setQuestion} placeholder="Is it safe to open?"
        multiline maxLength={1000} style={{ minHeight: 70, paddingTop: 12, textAlignVertical: 'top' }} />
      <Button label="Ask" kind="secondary" onPress={ask} busy={busy && !!chat.length} disabled={!question.trim()} />
      <ErrorText>{error}</ErrorText>
      <Text style={{ color: colors.faint, fontSize: 12, lineHeight: 18 }}>{"AI can make mistakes. The verdict comes from MyScanner's checks, not from the AI. Never type passwords or personal data."}</Text>
    </Card>
  );
}
