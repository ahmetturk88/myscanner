/**
 * Something shared to MyScanner from another app: a message, a link or a screenshot.
 * Nothing is opened and nothing leaves the phone until the person taps "Inspect" on one link.
 * Screenshots are searched for QR codes on the phone itself.
 */
import { scanFromURLAsync } from 'expo-camera';
import { router, useLocalSearchParams } from 'expo-router';
import { useEffect, useState } from 'react';
import { StyleSheet, Text, View } from 'react-native';
import Animated from 'react-native-reanimated';

import { enter } from '@/components/motion';
import { Screen } from '@/components/screen';
import { Button, ErrorText, Muted } from '@/components/ui';
import { t } from '@/lib/i18n';
import { startUrlScan } from '@/lib/scan';
import { colors, fonts } from '@/lib/theme';
import { findLinks } from '@/lib/tools';

const PREVIEW = 600;

export default function Shared() {
  const { text = '', image = '' } = useLocalSearchParams<{ text?: string; image?: string }>();
  const [codes, setCodes] = useState<string[] | null>(image ? null : []);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!image) return;
    let alive = true;
    scanFromURLAsync(image, ['qr'])
      .then((found) => { if (alive) setCodes(found.map((c) => c.data).filter(Boolean)); })
      .catch(() => { if (alive) setCodes([]); });
    return () => { alive = false; };
  }, [image]);

  const fromText = findLinks(text);
  const fromCodes = (codes ?? []).flatMap((code) => findLinks(code));
  const links = [...fromText, ...fromCodes.filter((l) => !fromText.includes(l))].slice(0, 10);
  const plainCodes = (codes ?? []).filter((code) => !findLinks(code).length);
  const reading = image && codes === null;

  async function inspect(link: string) {
    setBusy(link); setError(null);
    try { await startUrlScan(link, true); } catch (e: any) { setError(e.message); setBusy(null); }
  }

  const heading = reading ? t('Reading the image…') : links.length ? t("Don't open it yet.") : t('No link found.');
  return (
    <Screen back title={t('Shared with MyScanner')} eyebrow={t('Shared · not opened')} largeTitle={heading}>
      {text ? (
        <Animated.View entering={enter(1)} style={s.card}>
          <Text style={s.label}>{t('What you shared')}</Text>
          <View style={s.quote}>
            <Text selectable style={s.quoteText}>{text.length > PREVIEW ? text.slice(0, PREVIEW) + '…' : text}</Text>
          </View>
        </Animated.View>
      ) : null}

      {links.length ? (
        <Animated.View entering={enter(2)} style={s.card}>
          <Text style={s.label}>{links.length === 1 ? t('Link in it') : t('Links in it ({count})', { count: links.length })}</Text>
          {links.map((link) => (
            <View key={link} style={s.link}>
              <Text selectable numberOfLines={2} style={s.linkText}>{link}</Text>
              <Button label={t('Inspect this URL')} arrow="→" onPress={() => inspect(link)} busy={busy === link} disabled={!!busy && busy !== link} />
            </View>
          ))}
          <Muted>{t('Messages like this often hide phishing links. Check where a link really leads before you open it.')}</Muted>
        </Animated.View>
      ) : null}

      {plainCodes.length ? (
        <Animated.View entering={enter(3)} style={s.card}>
          <Text style={s.label}>{t('QR code in the image')}</Text>
          {plainCodes.map((code) => <View key={code} style={s.quote}><Text selectable style={s.quoteText}>{code}</Text></View>)}
          <Muted>{t('It is not a web link, so there is nothing to scan online.')}</Muted>
        </Animated.View>
      ) : null}

      {!reading && !links.length ? (
        <Animated.View entering={enter(3)} style={s.card}>
          <Muted>{image
            ? t('We found no QR code or link in this image. Reading the text of a screenshot is coming; for now, share the message text itself or copy the link.')
            : t('There is no web link in this text, so there is nothing to scan. If a message asks for money, a code or your password, do not reply.')}</Muted>
        </Animated.View>
      ) : null}

      <ErrorText>{error}</ErrorText>
      <Muted>{t('Nothing you share leaves your phone until you tap Inspect on a link.')}</Muted>
      <Button label={t('Done')} kind="secondary" onPress={() => (router.canGoBack() ? router.back() : router.replace('/'))} />
    </Screen>
  );
}

const s = StyleSheet.create({
  card: { gap: 12, padding: 18, borderRadius: 24, borderWidth: 1, borderColor: colors.line, backgroundColor: 'rgba(14,24,37,.9)' },
  label: { color: colors.text, fontSize: 15, fontFamily: fonts.bold },
  quote: { padding: 12, borderRadius: 12, backgroundColor: colors.input, borderWidth: 1, borderColor: colors.line },
  quoteText: { color: colors.soft, fontSize: 14.5, lineHeight: 21, fontFamily: fonts.regular },
  link: { gap: 10, paddingTop: 6 },
  linkText: { color: colors.amber, fontSize: 15, fontFamily: fonts.semibold },
});
