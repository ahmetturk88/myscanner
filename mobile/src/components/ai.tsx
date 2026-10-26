import * as Clipboard from 'expo-clipboard';
import * as Haptics from '@/lib/haptics';
import { LinearGradient } from 'expo-linear-gradient';
import { useRef, useState } from 'react';
import { Pressable, Text, TextInput, View } from 'react-native';

import { Icon } from '@/components/icon';
import { TypingDots } from '@/components/motion';
import { Button, Card, ErrorText, Muted, styles as ui } from '@/components/ui';
import { api, plain, stream } from '@/lib/api';
import { t, upper } from '@/lib/i18n';
import { getSettings } from '@/lib/settings';
import { colors, fonts, gradients } from '@/lib/theme';

type Explanation = {
  headline: string; summary: string;
  reasons: { point: string; evidence: string }[];
  next_steps: string[]; not_checked: string[]; technical_notes: string[];
};

const LABELS: Record<string, keyof Explanation> = {
  'WHY THIS RESULT': 'reasons', 'WHAT TO DO NOW': 'next_steps', 'NOT CONFIRMED': 'not_checked', 'TECHNICAL NOTES': 'technical_notes',
};
const sections = (): [keyof Explanation, string, string][] => [
  ['reasons', t('Why this result'), colors.cyan], ['next_steps', t('What to do now'), colors.green],
  ['not_checked', t('What was not confirmed'), colors.amber], ['technical_notes', t('Technical notes'), colors.muted],
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
      {data.headline ? <DirectedText text={data.headline} style={{ color: colors.text, fontSize: 18, fontFamily: fonts.bold, lineHeight: 26 }} /> : null}
      {data.summary ? <DirectedText text={data.summary} style={ui.body} /> : null}
      {sections().map(([key, title, tint]) => {
        const items = data[key] as any[];
        if (!items.length) return null;
        return (
          <View key={key} style={{ gap: 6, borderTopWidth: 1, borderTopColor: colors.line, paddingTop: 10 }}>
            <Text style={{ color: tint, fontSize: 12, fontFamily: fonts.mono, letterSpacing: 1.5 }}>{upper(title)}</Text>
            {items.map((item, i) => {
              const point = typeof item === 'string' ? item : item.point;
              const rtl = isRtl(point);
              return (
                <View key={i} style={{ gap: 2 }}>
                  <Text style={[ui.body, { writingDirection: rtl ? 'rtl' : 'ltr', textAlign: rtl ? 'right' : 'left' }]}>{'•  '}{point}</Text>
                  {typeof item === 'object' && item.evidence ? (
                    <Text style={{ color: colors.faint, fontSize: 13, paddingHorizontal: 16, writingDirection: rtl ? 'rtl' : 'ltr', textAlign: rtl ? 'right' : 'left' }}>{item.evidence}</Text>
                  ) : null}
                </View>
              );
            })}
          </View>
        );
      })}
    </View>
  );
}

const RTL_LETTERS = /[\u0590-\u08FF\uFB1D-\uFDFF\uFE70-\uFEFF]/g;
const LTR_LETTERS = /[A-Za-z\u00C0-\u024F]/g;

/** Right-to-left when most letters on the line are Arabic (or Hebrew); English terms inside don't flip it. */
export function isRtl(line: string) {
  return (line.match(RTL_LETTERS)?.length ?? 0) > (line.match(LTR_LETTERS)?.length ?? 0);
}

/** Text laid out line by line, so a reply mixing Arabic and English keeps each line's own direction. */
export function DirectedText({ text, style }: { text: string; style: any }) {
  const lines = text.split('\n');
  return (
    <View style={{ gap: 2 }}>
      {lines.map((line, i) => {
        const rtl = isRtl(line);
        return (
          <Text key={i} selectable style={[style, { writingDirection: rtl ? 'rtl' : 'ltr', textAlign: rtl ? 'right' : 'left' }]}>
            {line || ' '}
          </Text>
        );
      })}
    </View>
  );
}

/** A small "Copy" action under an AI answer; confirms with a tick and a haptic. */
export function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    await Clipboard.setStringAsync(text).catch(() => {});
    Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }
  return (
    <Pressable accessibilityRole="button" accessibilityLabel={t('Copy answer')} onPress={copy} hitSlop={8}
      style={{ flexDirection: 'row', alignItems: 'center', gap: 6, alignSelf: 'flex-start', paddingVertical: 4, paddingHorizontal: 2 }}>
      <Icon name={copied ? 'check' : 'copy'} size={14} color={copied ? colors.green : colors.faint} />
      <Text style={{ color: copied ? colors.green : colors.faint, fontSize: 12.5, fontFamily: fonts.medium }}>{copied ? t('Copied') : t('Copy')}</Text>
    </Pressable>
  );
}

/** The explanation as plain text, for copying or sharing. */
function explanationText(data: Explanation) {
  const parts = [data.headline, data.summary].filter(Boolean);
  for (const [key, title] of sections()) {
    const items = data[key] as any[];
    if (!items.length) continue;
    parts.push('', upper(title), ...items.map((item) => `• ${typeof item === 'string' ? item : item.point}${typeof item === 'object' && item.evidence ? ` (${item.evidence})` : ''}`));
  }
  return parts.join('\n');
}

export function Bubble({ role, text }: { role: 'user' | 'assistant'; text: string }) {
  const mine = role === 'user';
  const body = text ? <DirectedText text={text} style={{ color: colors.text, fontSize: 15, lineHeight: 24, fontFamily: fonts.regular }} /> : <TypingDots />;
  if (mine) {
    return (
      <LinearGradient colors={gradients.user} start={{ x: 0, y: 0 }} end={{ x: 1, y: 1 }}
        style={{ alignSelf: 'flex-end', maxWidth: '86%', borderRadius: 20, borderBottomRightRadius: 6, paddingVertical: 11, paddingHorizontal: 15 }}>
        {body}
      </LinearGradient>
    );
  }
  return (
    <View style={{ alignSelf: 'flex-start', maxWidth: '90%', gap: 2 }}>
      <View style={{ backgroundColor: colors.surface2, borderRadius: 20, borderBottomLeftRadius: 6,
        borderWidth: 1, borderColor: colors.line, paddingVertical: 11, paddingHorizontal: 15 }}>
        {body}
      </View>
      {text ? <CopyButton text={text} /> : null}
    </View>
  );
}

/** "Explain this report" plus follow-up questions, for any finished report. */
export function AIPanel({ tool, evidence }: { tool: string; evidence: unknown }) {
  const context = useRef<string | null>(null);
  const [explanation, setExplanation] = useState<Explanation | null>(null);
  const [explaining, setExplaining] = useState(false);
  const [chat, setChat] = useState<{ role: 'user' | 'assistant'; text: string }[]>([]);
  const [question, setQuestion] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function ensureContext() {
    if (!context.current) context.current = (await api.createContext(tool, evidence)).id;
    return context.current;
  }

  async function explain() {
    setBusy(true); setExplaining(true); setError(null);
    try {
      const id = await ensureContext();
      const final = await stream(`/ai/contexts/${id}/explain`, { language: getSettings().language }, (text) => setExplanation(parse(text)));
      setExplanation(final.explanation);
      Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success).catch(() => {});
    } catch (e: any) {
      setError(e.message);
    } finally { setBusy(false); setExplaining(false); }
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
    <Card glow>
      <Text style={ui.kicker}>{t('✦ AI ASSISTANT')}</Text>
      {!explanation && !explaining ? (
        <>
          <Text style={{ color: colors.text, fontSize: 21, fontFamily: fonts.bold, letterSpacing: -0.4 }}>{t('Understand this report')}</Text>
          <Muted>{t('A plain-language explanation of the evidence, then ask follow-up questions. Uses 1 of your daily AI answers.')}</Muted>
          <Button label={t('Explain with AI')} icon="spark" onPress={explain} />
        </>
      ) : explanation ? <ExplanationView data={explanation} /> : <TypingDots />}
      {explanation && !explaining ? <CopyButton text={explanationText(explanation)} /> : null}
      {chat.map((m, i) => <Bubble key={i} role={m.role} text={m.text} />)}
      {explanation && !explaining ? (
        <View style={[ui.inputWrap, { paddingRight: 6 }]}>
          <TextInput value={question} onChangeText={setQuestion} placeholder={t('Ask about this report…')} placeholderTextColor={colors.faint}
            style={ui.input} multiline maxLength={1000} />
          <Pressable accessibilityRole="button" accessibilityLabel={t('Ask')} onPress={ask} disabled={!question.trim() || busy}
            style={{ opacity: !question.trim() || busy ? 0.5 : 1 }}>
            <LinearGradient colors={gradients.accent} style={{ width: 40, height: 40, borderRadius: 12, alignItems: 'center', justifyContent: 'center' }}>
              <Icon name="send" size={18} color={colors.onAccent} />
            </LinearGradient>
          </Pressable>
        </View>
      ) : null}
      <ErrorText>{error}</ErrorText>
      <Text style={{ color: colors.faint, fontSize: 12, lineHeight: 18, fontFamily: fonts.regular }}>{t("AI can make mistakes. The verdict comes from MyScanner's checks, not from the AI. Never type passwords or personal data.")}</Text>
    </Card>
  );
}
