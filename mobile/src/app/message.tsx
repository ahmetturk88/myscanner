/**
 * Message check: choose a screenshot (or share one, or share a message's text, to MyScanner).
 * The server reads it, hides personal data, scans every link in it in the isolated browser and its AI
 * reviews the hidden text. One loading screen until everything is done, then the verdict, the AI review
 * and the links, each with a coloured dot that opens its saved report. A QR code in the screenshot is
 * decoded here on the phone and checked with the rest.
 */
import { scanFromURLAsync } from 'expo-camera';
import * as DocumentPicker from 'expo-document-picker';
import * as Haptics from '@/lib/haptics';
import { router, useLocalSearchParams } from 'expo-router';
import { useEffect, useRef, useState } from 'react';
import { Image, Pressable, StyleSheet, Text, View } from 'react-native';
import Animated from 'react-native-reanimated';

import { HowItWorks } from '@/components/how';
import { Icon } from '@/components/icon';
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

type Shot = { uri: string; name: string; mimeType?: string | null };
type LinkState = 'bad' | 'warn' | 'ok' | 'official' | 'scanning' | 'na';
type Link = { link: string; shown: string; state: LinkState; scan_id?: number | null; notes?: string[]; same_site?: number };
type Source = { key: string; name: string; url: string | null; how: string };
const OFFICIAL_URL = /^https:\/\/[a-z0-9.-]+\/?$/;
const STATE = (): Record<LinkState, string> => ({
  bad: t('Dangerous'), warn: t('Suspicious'), ok: t('No threat found'), official: t('Official site'),
  scanning: t('Still scanning'), na: t('Not checked'),
});
const DOT: Record<LinkState, string> = { bad: colors.red, warn: colors.amber, ok: colors.green, official: colors.green, scanning: colors.faint, na: colors.faint };
/** What to do right away when the message already got to you. */
const HELP = () => [
  t('Call your bank now on the number on your card or in its app, and ask them to block the card and stop the payment.'),
  t('If you shared a code, change that account’s password and turn on two-step verification. For WhatsApp: Settings, Account, Two-step verification.'),
  t('If you installed an app from the message, turn on airplane mode and remove the app, then tell your bank.'),
  t('Report it to usom.gov.tr and keep screenshots; for money lost, file a complaint with the police or the prosecutor’s office.'),
];
function linkNote(note: string) {
  if (note === 'listed as dangerous by a threat list') return t('Listed as dangerous');
  if (note === 'short link: the real address is hidden') return t('Short link: the real address is hidden');
  const lookalike = /^Possible typosquatting of (.+)$/.exec(note);
  return lookalike ? t('May imitate {domain}', { domain: lookalike[1] }) : note;
}
const isEmail = (file: { name?: string | null; mimeType?: string | null }) => /\.eml$/i.test(file.name ?? '') || file.mimeType === 'message/rfc822';
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** QR codes in a screenshot, decoded on the phone. */
async function codesIn(uri: string) {
  try { return (await scanFromURLAsync(uri, ['qr'])).map((c) => c.data).filter(Boolean); } catch { return []; }
}

export default function MessageCheck() {
  const TOOL = toolByName('message')!;
  const params = useLocalSearchParams<{ text?: string; image?: string }>();
  const [shot, setShot] = useState<Shot | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [help, setHelp] = useState(false);
  const [editing, setEditing] = useState<string | null>(null);
  const [showRead, setShowRead] = useState(false);
  const [answered, setAnsweredText] = useState<string | null>(null);
  const started = useRef(false);

  /** One check: a screenshot, or a message's text shared from another app. Waits for the link scans. */
  async function check(image: Shot | null, text = '', previous?: string) {
    if (!image && !text.trim()) return;
    setBusy(true); setError(null); setResult(null); setHelp(false); setAnsweredText(null); setEditing(null); setShowRead(false);
    setShot(image && !isEmail(image) ? image : null);
    try {
      let message = text;
      if (image && !isEmail(image)) {
        const codes = await codesIn(image.uri);
        if (codes.length) message = [message, ...codes].filter(Boolean).join('\n');
      }
      let data: any = image
        ? await upload('/tools/message', image, undefined, { field: isEmail(image) ? 'email' : 'image',
          // The original email of the message just checked builds on that check instead of starting again.
          fields: { text: message.slice(0, 6000), lang: lang(), ...(isEmail(image) && previous ? { previous } : {}) } })
        : await api.tool('message', { text: message.slice(0, 6000), lang: lang() });
      // The links are being scanned in the isolated browser: ask until all are done (about two minutes at most).
      for (let round = 0; data?.status === 'scanning' && data?.token; round++) {
        const token = data.token;
        await wait(round < 10 ? 2500 : 4000);
        data = await api.tool('message-finish', { token, final: round >= 32 });
        if (data?.status === 'scanning') data.token = token;
      }
      setResult(data);
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
    check(params.image ? { uri: params.image, name: 'shared.png', mimeType: 'image/png' } : null, params.text ?? '');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function choose(emailOnly = false) {
    const picked = await DocumentPicker.getDocumentAsync({ type: emailOnly ? ['message/rfc822', 'application/octet-stream'] : ['image/png', 'image/jpeg', 'image/webp', 'message/rfc822'],
      copyToCacheDirectory: true, multiple: false });
    if (picked.canceled || !picked.assets?.[0]) return;
    const asset = picked.assets[0];
    if (asset.size && asset.size > 8 * 1024 * 1024) { setError(t('The file is too large (8 MB at most).')); return; }
    if (emailOnly && !isEmail(asset)) { setError(t('Choose the email file that ends in .eml.')); return; }
    check({ uri: asset.uri, name: asset.name, mimeType: asset.mimeType }, '', typeof result?.token === 'string' ? result.token : undefined);
  }

  const again = () => { setResult(null); setShot(null); setError(null); setHelp(false); setAnsweredText(null); setEditing(null); setShowRead(false); };
  // "Was this right?": only our verdict, the answer and the sign keys go back; never the message.
  const answer = (value: 'real' | 'scam') => {
    const warned = result?.plain?.tone === 'danger' || result?.plain?.tone === 'caution';
    if (value === 'scam' && !warned) {
      setHelp(true);
      setAnsweredText(t('Thank you, we will look into it to improve the check. If you already tapped, paid or shared a code, follow the steps above now.'));
    } else if (value === 'real' && warned) {
      setAnsweredText(t('Thank you, we will look into it. To be sure, open the company’s official app or site yourself, never through the message.'));
    } else {
      setAnsweredText(t('Thank you, that confirms the check got it right.'));
    }
    api.tool('message-feedback', { tone: result?.plain?.tone, answer: value, signals: result?.signals ?? [] }).catch(() => {});
  };
  const open = (id: number) => router.push({ pathname: '/scan/[id]', params: { id: String(id) } });
  const risky = result?.plain?.tone === 'danger' || result?.plain?.tone === 'caution';
  const links: Link[] = result?.links ?? [];
  const reasons: string[] = [result?.plain?.ai_summary, ...(result?.plain?.ai_reasons ?? [])].filter((r) => typeof r === 'string' && r);
  const asks: string[] = result?.asks ?? [];
  const sources: Source[] = result?.verify ?? [];

  return (
    <Screen back title={TOOL.title} eyebrow={TOOL.kicker} badge={<ToolBadge tool={TOOL} busy={busy} />}
      largeTitle={<Accent text={TOOL.heading} accent={TOOL.accent} />} subtitle={TOOL.menu}>
      {!result && !busy ? (
        <>
          <ToolChips tool={TOOL} />
          <Animated.View entering={enter(2)}>
            <Pressable onPress={() => choose()} accessibilityRole="button" accessibilityLabel={t('Choose a screenshot')} style={s.drop}>
              <Icon name="image" size={44} color={colors.cyan} />
              <Text style={s.dropTitle}>{t('Choose a screenshot of the message')}</Text>
              <Text style={s.dropText}>{t('Or share a message or a screenshot to MyScanner from WhatsApp, Messages or your gallery.')}</Text>
              <View style={{ alignSelf: 'stretch' }}><Button label={t('Choose a screenshot')} icon="image" onPress={() => choose()} /></View>
            </Pressable>
          </Animated.View>
          <Muted>{t('Personal data is hidden first. The screenshot is read on our server and deleted at once. Links are scanned in our isolated browser, never on your phone.')}</Muted>
          <ErrorText>{error}</ErrorText>
        </>
      ) : null}
      {busy ? (
        <>
          {shot ? <Image source={{ uri: shot.uri }} style={s.thumb} resizeMode="cover" /> : null}
          <Working steps={[t('Reading the screenshot'), t('Hiding personal data'), t('Scanning the links in our isolated browser'),
            t('Writing the summary')]} every={3000} />
        </>
      ) : null}
      {result && hasPlain(result.plain) ? (
        <PlainReport plain={result.plain} haptic plainShare again={{ label: t('Check another screenshot'), onPress: again }}>
          {result.with_email ? (
            <Text style={s.withEmail}>✓ {t('Checked again with the original email: its real links and sender are below.')}</Text>
          ) : null}
          {reasons.length ? (
            <Animated.View entering={enter(4)} style={[s.card, s.ai]}>
              <Text style={s.title}>{t('Summary')}</Text>
              {result.sender ? <Text style={s.from}>{t('Claims to be from: {name}', { name: result.sender })}</Text> : null}
              {reasons.map((r) => <Text key={r} style={s.body}>{r}</Text>)}
            </Animated.View>
          ) : null}
          {result.hidden_link ? (
            <Animated.View entering={enter(4)} style={[s.card, s.eml]}>
              <Text style={[s.title, { color: '#fde68a' }]}>{t('The link is hidden behind a button')}</Text>
              <Text style={s.body}>{t('A screenshot can’t show where an email’s button leads. Send us the original email and we will check its real links and its sender.')}</Text>
              <Text style={s.body}>1. {t('In the Gmail app this isn’t possible: open gmail.com in your phone’s browser, or forward the email to yourself and download it on a computer (⋮ › Download message).')}</Text>
              <Text style={s.body}>2. {t('Save the .eml file, then choose it here.')}</Text>
              <Button label={t('Choose the email file (.eml)')} icon="doc" kind="secondary" onPress={() => choose(true)} />
            </Animated.View>
          ) : null}
          {links.length ? (
            <Animated.View entering={enter(5)} style={s.card}>
              <Text style={s.title}>{t('Links in the message')}</Text>
              {links.map((l) => {
                const state: LinkState = STATE()[l.state] ? l.state : 'na';
                const row = (
                  <View style={s.linkRow}>
                    <View style={[s.dot, { backgroundColor: DOT[state] }]} />
                    <View style={{ flex: 1, gap: 3 }}>
                      <Text numberOfLines={2} style={s.link}>{l.shown}</Text>
                      <Text style={[s.state, { color: DOT[state] }]}>{STATE()[state]}</Text>
                      {l.notes?.map((note, i) => <Text key={i} style={s.note}>{linkNote(note)}</Text>)}
                      {l.same_site ? <Text style={s.note}>{t('+{n} more links to the same site', { n: l.same_site })}</Text> : null}
                    </View>
                    {l.scan_id ? <Icon name="chevron" size={18} color={colors.faint} /> : null}
                  </View>
                );
                return l.scan_id ? (
                  <Pressable key={l.link} onPress={() => open(l.scan_id!)} accessibilityRole="button" accessibilityLabel={t('Open the report')}>{row}</Pressable>
                ) : <View key={l.link}>{row}</View>;
              })}
              <Muted>{t('Tap a link to open its full report. Links are never opened on your phone.')}</Muted>
            </Animated.View>
          ) : null}
          {asks.length ? (
            <Animated.View entering={enter(6)} style={s.card}>
              <Text style={s.title}>{t('What the message asks you to do')}</Text>
              {asks.map((a) => <Text key={a} style={[s.body, { color: colors.amber }]}>• {a}</Text>)}
            </Animated.View>
          ) : null}
          {sources.length ? (
            <Animated.View entering={enter(6)} style={[s.card, s.source]}>
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
          {risky ? (
            <Animated.View entering={enter(7)} style={[s.card, s.help]}>
              <Text onPress={() => setHelp(!help)} accessibilityRole="button" style={s.helpTitle}>
                {help ? '▾ ' : '▸ '}{t('Already tapped the link, paid or shared a code?')}
              </Text>
              {help ? HELP().map((step, i) => <Text key={step} style={s.body}>{i + 1}. {step}</Text>) : null}
            </Animated.View>
          ) : null}
          {result.text && !showRead ? (
            <Text onPress={() => setShowRead(true)} accessibilityRole="button" style={s.readLink}>{t('Didn’t we read it right? See and fix the text')}</Text>
          ) : null}
          {result.text && showRead ? (
            <Animated.View entering={enter(1)} style={s.card}>
              <Text style={s.title}>{t('Text read from the image (personal data hidden)')}</Text>
              {editing === null ? (
                <>
                  <Text selectable style={s.body}>{result.text}</Text>
                  {result.source !== 'email' ? (
                    <Button label={t('Edit the extracted text')} icon="doc" kind="secondary" onPress={() => setEditing(String(result.text).slice(0, 6000))} />
                  ) : null}
                </>
              ) : (
                <>
                  <Field label={t('Correct what was read wrong')} value={editing} onChangeText={setEditing} multiline
                    style={{ minHeight: 120, textAlignVertical: 'top' }} autoCorrect={false} maxLength={6000} />
                  <Button label={t('Check the corrected text')} arrow="→" disabled={!editing.trim()} onPress={() => check(null, editing)} />
                </>
              )}
            </Animated.View>
          ) : null}
          <Animated.View entering={enter(9)} style={s.card}>
            {answered ? (
              <>
                <Text style={s.body}>{answered}</Text>
                <Muted>{t('We keep only the verdict and the signs we found, never the message.')}</Muted>
              </>
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
  drop: { alignItems: 'center', gap: 12, padding: 24, borderRadius: 24, borderWidth: 2, borderStyle: 'dashed', borderColor: 'rgba(94,234,212,.45)', backgroundColor: 'rgba(8,20,35,.92)' },
  dropTitle: { color: colors.text, fontSize: 18, fontFamily: fonts.bold, textAlign: 'center' },
  dropText: { color: colors.soft, fontSize: 14, lineHeight: 20, fontFamily: fonts.regular, textAlign: 'center' },
  thumb: { alignSelf: 'center', width: 84, height: 84, borderRadius: 18, borderWidth: 1, borderColor: colors.line },
  card: { gap: 12, padding: 18, borderRadius: 24, borderWidth: 1, borderColor: colors.line, backgroundColor: 'rgba(14,24,37,.9)' },
  ai: { borderColor: 'rgba(125,211,252,.4)', backgroundColor: 'rgba(16,28,58,.94)' },
  title: { color: colors.text, fontSize: 15.5, fontFamily: fonts.bold },
  body: { color: colors.soft, fontSize: 14.5, lineHeight: 21, fontFamily: fonts.regular },
  linkRow: { flexDirection: 'row', alignItems: 'center', gap: 12, padding: 12, borderRadius: 16, backgroundColor: colors.input, borderWidth: 1, borderColor: colors.line },
  dot: { width: 12, height: 12, borderRadius: 6 },
  link: { color: colors.text, fontSize: 14, fontFamily: fonts.mono },
  note: { color: colors.faint, fontSize: 12.5, fontFamily: fonts.regular },
  state: { fontSize: 11.5, fontFamily: fonts.bold, letterSpacing: 0.6 },
  source: { borderColor: 'rgba(94,234,212,.35)', backgroundColor: 'rgba(10,30,32,.92)' },
  withEmail: { color: '#9fe8d6', fontSize: 14, fontFamily: fonts.semibold, padding: 12, borderRadius: 14, borderWidth: 1,
    borderColor: 'rgba(94,234,212,.35)', backgroundColor: 'rgba(10,30,32,.92)' },
  from: { color: colors.cyan, fontSize: 13, fontFamily: fonts.semibold },
  eml: { borderColor: 'rgba(251,191,36,.45)', backgroundColor: 'rgba(36,26,8,.92)' },
  readLink: { color: colors.cyan, fontSize: 13.5, fontFamily: fonts.semibold, textAlign: 'center', paddingVertical: 6 },
  help: { borderColor: 'rgba(251,113,133,.45)', backgroundColor: 'rgba(40,14,24,.92)' },
  helpTitle: { color: '#fecdd3', fontSize: 15.5, fontFamily: fonts.bold, paddingVertical: 4 },
});
