/**
 * Open a web page from the app. Some phones have no browser enabled at all, and
 * then expo-web-browser rejects ("No matching browser activity found"). We try the
 * in-app browser tab first, then any app that opens links, and finally tell the
 * person what is missing instead of failing silently.
 */
import * as WebBrowser from 'expo-web-browser';
import { Alert, Linking } from 'react-native';

import { t } from '@/lib/i18n';

/** True when the error means the phone has no app that can open a web page. */
export function isNoBrowser(error: unknown) {
  const message = String((error as { message?: string })?.message ?? error);
  return /no matching browser|ActivityNotFound|No Activity found/i.test(message);
}

export async function openLink(url: string) {
  try {
    await WebBrowser.openBrowserAsync(url);
    return;
  } catch {
    // fall through to the system handler
  }
  try {
    await Linking.openURL(url);
    return;
  } catch {
    // fall through to the explanation
  }
  Alert.alert(t('No web browser found'), t('Install or turn on a web browser (for example Chrome), or open this address on another device:') + `\n\n${url}`);
}
