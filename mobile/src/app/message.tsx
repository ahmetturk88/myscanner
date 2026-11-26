/**
 * Message check: paste a message, share one from another app, or choose a screenshot.
 * The server hides personal data first, checks the links without opening them and gives a
 * plain verdict. A screenshot is read on our server and deleted at once; a QR code in it is
 * decoded here on the phone and added to the text.
 */
import * as Clipboard from 'expo-clipboard';
import { scanFromURLAsync } from 'expo-camera';
import * as DocumentPicker from 'expo-document-picker';
import * as Haptics from '@/lib/haptics';
import { useLocalSearchParams } from 'expo-router';
import { useEffect, useRef, useState } from 'react';
import { StyleSheet, Text, View } from 'react-native';
import Animated from 'react-native-reanimated';

import { HowItWorks } from '@/components/how';
import { enter } from '@/components/motion';
import { hasPlain, PlainReport } from '@/components/report';
import { Screen } from '@/components/screen';
import { Accent, ToolBadge, ToolChips } from '@/components/tool-hero';
import { Button, ErrorText, Field, Muted } from '@/components/ui';
import { Working } from '@/components/working';
import { api, upload } from '@/lib/api';
import { lang, t } from '@/lib/i18n';
import { openLink } from '@/lib/open-link';
import { colors, fonts } from '@/lib/theme';
import { toolByName } from '@/lib/tools';

type Source = { key: string; name: string; url: string | null; how: string };
const OFFICIAL_URL = /^https:\/\/[a-z0-9.-]+\/?$/;
type Shot = { uri: string; name: string; mimeType?: string | null };
type Link = { shown: string; state: 'bad' | 'warn' | 'ok' | 'official' | 'na'; notes: string[] };
const STATE = () => ({ bad: t('Listed as dangerous'), warn: t('Suspicious'), ok: t('Not listed'), official: t('Official site'), na: t('Not checked') });
const TONE = { bad: colors.red, warn: colors.amber, ok: colors.green, official: colors.green, na: colors.faint };
function linkNote(note: string) {
  if (note === 'listed as dangerous by a threat list') return t('Listed as dangerous');
  if (note === 'short link: the real address is hidden') return t('Short link: the real address is hidden');
  const lookalike = /^Possible typosquatting of (.+)$/.exec(note);
  return lookalike ? t('May imitate {domain}', { domain: lookalike[1] }) : note;
}
/** What to do right away when the message already got to you. */
const HELP = () => [
  t('Call your bank now on the number on your card or in its app, and ask them to block the card and stop the payment.'),
  t('If you shared a code, change that account’s password and turn on two-step verification. For WhatsApp: Settings, Account, Two-step verification.'),
  t('If you installed an app from the message, turn on airplane mode and remove the app, then tell your bank.'),
  t('Report it to usom.gov.tr and keep screenshots; for money lost, file a complaint with the police or the prosecutor’s office.'),
];

/** QR codes in a screenshot, decoded on the phone. */
async function codesIn(uri: string) {
  try { return (await scanFromURLAsync(uri, ['qr'])).map((c) => c.data).filter(Boolean); } catch { return []; }
}

export default function MessageCheck() {
  const TOOL = toolByName('message')!;
  const params = useLocalSearchParams<{ text?: string; image?: string }>();
  const [text, setText] = useState(params.text ?? '');
  const [shot, setShot] = useState<Shot | null>(params.image ? { uri: params.image, name: 'shared.png', mimeType: 'image/png' } : null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [help, setHelp] = useState(false);
  const [answered, setAnswered] = useState(false);
  const started = useRef(false);

  async function check(current = text, image = shot) {
    if (!current.trim() && !image) return;
    setBusy(true); setError(null); setResult(null);
    try {
      let message = current;
      if (image) {
        const codes = await codesIn(image.uri);
        if (codes.length) message = [message, ...codes].filter(Boolean).join('\n');
      }
      const data: any = image
        ? await upload('/tools/message', image, undefined, { field: 'image', fields: { text: message.slice(0, 6000), lang: lang() } })
        : await api.tool('message', { text: message.slice(0, 6000), lang: lang() });
      setResult(data); setAnswered(false);
      Haptics.notificationAsync(data?.plain?.tone === 'danger' ? Haptics.NotificationFeedbackType.Warning : Haptics.NotificationFeedbackType.Success).catch(() => {});
    } catch (e: any) {
      setError(e.message);
      Haptics.notificationAsync(Haptics.NotificationFeedbackType.Error).catch(() => {});
    } finally { setBusy(false); }
  }

  // Something shared to MyScanner is checked straight away.
  useEffect(() => {
    if (started.current || (!params.text && !params.image)) return;
    started.current = true;
    check(params.text ?? '', params.image ? { uri: params.image, name: 'shared.png', mimeType: 'image/png' } : null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function paste() {
    const value = await Clipboard.getStringAsync().catch(() => '');
    if (value.trim()) { setText(value.slice(0, 6000)); setError(null); } else setError(t('Your clipboard is empty.'));
  }

  async function choose() {
    const picked = await DocumentPicker.getDocumentAsync({ type: ['image/png', 'image/jpeg', 'image/webp'], copyToCacheDirectory: true, multiple: false });
    if (picked.canceled || !picked.assets?.[0]) return;
    const asset = picked.assets[0];
    if (asset.size && asset.size > 8 * 1024 * 1024) { setError(t('The image is too large (8 MB at most).')); return; }
    setShot({ uri: asset.uri, name: asset.name, mimeType: asset.mimeType }); setError(null);
  }

  const again = () => { setResult(null); setText(''); setShot(null); setError(null); setHelp(false); setAnswered(false); };
  // "Was this right?": only our verdict, the answer and the sign keys go back; never the message.
  const answer = (value: 'real' | 'scam') => {
    setAnswered(true);
    api.tool('message-feedback', { tone: result?.plain?.tone, answer: value, signals: result?.signals ?? [] }).catch(() => {});
  };
  const asks: string[] = result?.asks ?? [];
  const sources: Source[] = result?.verify ?? [];
  const risky = result?.plain?.tone === 'danger' || result?.plain?.tone === 'caution';
  const links: Link[] = result?.links ?? [];
  const reasons: string[] = result?.plain?.ai_reasons ?? [];

  return (
    <Screen back title={TOOL.title} eyebrow={TOOL.kicker} badge={<ToolBadge tool={TOOL} busy={busy} />}
      largeTitle={<Accent text={TOOL.heading} accent={TOOL.accent} />} subtitle={TOOL.menu}>
      {!result ? (
        <>
          <ToolChips tool={TOOL} />
          <Animated.View entering={enter(2)} style={s.card}>
            <Field label={t('The message')} value={text} onChangeText={setText} placeholder={t('Paste the message here')} multiline
              style={{ minHeight: 120, textAlignVertical: 'top' }} editable={!busy} autoCorrect={false} maxLength={6000} />
            <View style={{ flexDirection: 'row', gap: 10 }}>
              <Button label={t('Paste')} icon="paste" kind="secondary" flex={1} onPress={paste} disabled={busy} />
              <Button label={t('Screenshot')} icon="image" kind="secondary" flex={1} onPress={choose} disabled={busy} />
            </View>
            {shot ? (
              <View style={s.picked}>
                <Text numberOfLines={1} style={s.pickedText}>🖼 {shot.name}</Text>
                <Text onPress={() => setShot(null)} style={s.remove}>{t('Remove')}</Text>
              </View>
            ) : null}
            <Button label={t('Check the message')} arrow="→" onPress={() => check()} busy={busy} disabled={!text.trim() && !shot} />
            <Muted>{t('Personal data is hidden first. A screenshot is read on our server and deleted at once. Links are never opened.')}</Muted>
            <ErrorText>{error}</ErrorText>
          </Animated.View>
        </>
      ) : null}
      {busy ? <Working steps={[t('Reading the message'), t('Hiding personal data'), t('Checking the links'), t('Looking for scam tricks')]} every={2500} /> : null}
      {result && hasPlain(result.plain) ? (
        <PlainReport plain={result.plain} haptic plainShare again={{ label: t('Check another message'), onPress: again }}>
          {risky ? (
            <Animated.View entering={enter(5)} style={[s.card, s.help]}>
              <Text onPress={() => setHelp(!help)} accessibilityRole="button" style={s.helpTitle}>
                {help ? '▾ ' : '▸ '}{t('Already tapped the link, paid or shared a code?')}
              </Text>
              {help ? HELP().map((step, i) => <Text key={step} style={s.body}>{i + 1}. {step}</Text>) : null}
            </Animated.View>
          ) : null}
          {asks.length ? (
            <Animated.View entering={enter(5)} style={s.card}>
              <Text style={s.title}>{t('What the message asks you to do')}</Text>
              {asks.map((a) => <Text key={a} style={[s.body, { color: colors.amber }]}>• {a}</Text>)}
            </Animated.View>
          ) : null}
          {sources.length ? (
            <Animated.View entering={enter(5)} style={[s.card, s.source]}>
              <Text style={s.title}>{t('Check it yourself, at the source')}</Text>
              <Muted>{t('From our own list of official sites, never from the message. Open them yourself.')}</Muted>
              {sources.map((v) => (
                <View key={v.key} style={{ gap: 6 }}>
                  <Text style={[s.body, { color: colors.text, fontFamily: fonts.bold }]}>{v.name}</Text>
                  <Text style={s.body}>{v.how}</Text>
                  {v.url && OFFICIAL_URL.test(v.url) ? (
                    <Button label={t('Open the official site')} icon="external" kind="secondary" onPress={() => openLink(v.url!)} />
                  ) : null}
                </View>
              ))}
            </Animated.View>
          ) : null}
          {reasons.length ? (
            <Animated.View entering={enter(6)} style={s.card}>
              <Text style={s.title}>{t('What the AI review says')}</Text>
              {reasons.map((r) => <Text key={r} style={s.body}>• {r}</Text>)}
            </Animated.View>
          ) : null}
          {links.length ? (
            <Animated.View entering={enter(7)} style={s.card}>
              <Text style={s.title}>{t('Links in the message')}</Text>
              {links.map((l) => (
                <View key={l.shown} style={{ gap: 8 }}>
                  <Text selectable numberOfLines={2} style={s.link}>{l.shown}</Text>
                  <Text style={[s.state, { color: TONE[l.state] ?? colors.faint }]}>{STATE()[l.state] ?? ''}</Text>
                  {l.notes?.map((note, index) => <Text key={index} style={s.body}>{linkNote(note)}</Text>)}
                </View>
              ))}
            </Animated.View>
          ) : null}
          {result.text ? (
            <Animated.View entering={enter(8)} style={s.card}>
              <Text style={s.title}>{t('Text read from the image (personal data hidden)')}</Text>
              <Text selectable style={s.body}>{result.text}</Text>
              <Button label={t('Edit the extracted text')} kind="secondary" onPress={() => {
                again();
                setText(result.text.slice(0, 6000));
              }} />
            </Animated.View>
          ) : null}
          <Animated.View entering={enter(9)} style={s.card}>
            {answered ? (
              <Muted>{t('Thank you. We keep only the verdict and the signs we found, never the message.')}</Muted>
            ) : (
              <>
                <Text style={s.title}>{t('Was this result right?')}</Text>
                <View style={{ flexDirection: 'row', gap: 10 }}>
                  <Button label={t('The message was real')} kind="secondary" flex={1} onPress={() => answer('real')} />
                  <Button label={t('It was a scam')} kind="secondary" flex={1} onPress={() => answer('scam')} />
                </View>
              </>
            )}
          </Animated.View>
          <ErrorText>{error}</ErrorText>
        </PlainReport>
      ) : null}
      {!busy && !result ? <HowItWorks steps={TOOL.steps} /> : null}
    </Screen>
  );
}

const s = StyleSheet.create({
  card: { gap: 12, padding: 18, borderRadius: 24, borderWidth: 1, borderColor: colors.line, backgroundColor: 'rgba(14,24,37,.9)' },
  title: { color: colors.text, fontSize: 15.5, fontFamily: fonts.bold },
  body: { color: colors.soft, fontSize: 14.5, lineHeight: 21, fontFamily: fonts.regular },
  link: { color: colors.amber, fontSize: 14.5, fontFamily: fonts.semibold },
  state: { fontSize: 12, fontFamily: fonts.bold, letterSpacing: 0.6 },
  picked: { flexDirection: 'row', alignItems: 'center', gap: 10, padding: 12, borderRadius: 12, backgroundColor: colors.input, borderWidth: 1, borderColor: colors.line },
  pickedText: { flex: 1, color: colors.soft, fontSize: 14, fontFamily: fonts.regular },
  source: { borderColor: 'rgba(94,234,212,.35)', backgroundColor: 'rgba(10,30,32,.92)' },
  help: { borderColor: 'rgba(251,113,133,.45)', backgroundColor: 'rgba(40,14,24,.92)' },
  helpTitle: { color: '#fecdd3', fontSize: 15.5, fontFamily: fonts.bold, paddingVertical: 4 },
  remove: { color: colors.cyan, fontSize: 14, fontFamily: fonts.semibold },
});
