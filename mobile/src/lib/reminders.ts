/**
 * Safety reminders: short local notifications three times a day, six hours apart (09:00, 15:00,
 * 21:00 on the phone's clock; never at night).
 *
 * Private by design: they are scheduled on the phone itself. No push token is created, nothing is
 * sent to a server, and the text never contains anything about the user or their scans. A tap can
 * only open one of a fixed list of screens inside the app.
 *
 * The next two weeks are scheduled each time the app opens, in the app's language, so a phone that
 * isn't opened for a fortnight stops getting them instead of being reminded forever.
 */
import * as Notifications from 'expo-notifications';
import { Platform } from 'react-native';

import { t } from '@/lib/i18n';
import { getSettings, updateSettings } from '@/lib/settings';

const CHANNEL = 'safety-reminders';
const HOURS = [9, 15, 21] as const;
const DAYS = 14;

/** Screens a reminder may open. Anything else in a notification is ignored. */
export const REMINDER_ROUTES = ['/', '/qr', '/file', '/tool/email', '/tool/site', '/tool/password'] as const;
type Route = (typeof REMINDER_ROUTES)[number];

type Reminder = { title: string; body: string; route: Route };

/** Morning, afternoon and evening messages; each slot cycles through its own list day by day. */
function messages(): Record<(typeof HOURS)[number], Reminder[]> {
  return {
    9: [
      { title: t('Good morning'), body: t('Start the day safe: got a link in a message? Check it before you open it.'), route: '/' },
      { title: t('Good morning'), body: t('Banks and couriers never ask for your card or SMS code by message. When in doubt, check the sender.'), route: '/tool/email' },
      { title: t('Good morning'), body: t('A parcel “waiting for a fee”? Scam texts often start that way. Check the link first.'), route: '/' },
      { title: t('Good morning'), body: t('Strong passwords keep accounts safe. See how yours holds up in seconds.'), route: '/tool/password' },
      { title: t('Good morning'), body: t('Shopping online today? Check an unfamiliar shop before you pay.'), route: '/tool/site' },
    ],
    15: [
      { title: t('Quick safety check'), body: t('A QR code on a poster or a parking meter? Scan it with MyScanner before you pay.'), route: '/qr' },
      { title: t('Quick safety check'), body: t('Got a file you didn’t expect, like an invoice or an APK? Check it before you open it.'), route: '/file' },
      { title: t('Quick safety check'), body: t('A deal that looks too good to be true usually is. Check the shop’s website first.'), route: '/tool/site' },
      { title: t('Quick safety check'), body: t('Is that email really from your bank? Check the sender’s address in one tap.'), route: '/tool/email' },
      { title: t('Quick safety check'), body: t('A shortened link hides where it goes. MyScanner shows you the real address.'), route: '/' },
    ],
    21: [
      { title: t('Before you sleep'), body: t('Any links or files from today you weren’t sure about? Check them now in seconds.'), route: '/' },
      { title: t('Before you sleep'), body: t('Use a different password for every account. Check how strong yours are.'), route: '/tool/password' },
      { title: t('Before you sleep'), body: t('“Your account will be closed” messages are a classic scam. Check before you tap.'), route: '/' },
      { title: t('Before you sleep'), body: t('Downloaded an app outside Google Play? Let MyScanner check the file.'), route: '/file' },
      { title: t('Before you sleep'), body: t('Scammers copy shop websites. Check the address before you enter your card.'), route: '/tool/site' },
    ],
  };
}

/** Whether a route from a notification is one of ours. */
export function reminderRoute(value: unknown): Route | null {
  return typeof value === 'string' && (REMINDER_ROUTES as readonly string[]).includes(value) ? (value as Route) : null;
}

export async function permissionGranted() {
  if (Platform.OS === 'web') return false;
  const { granted } = await Notifications.getPermissionsAsync();
  return granted;
}

/** Asks Android/iOS for permission (only after the user tapped "Turn on"). */
export async function askPermission() {
  if (Platform.OS === 'web') return false;
  if (Platform.OS === 'android') {
    await Notifications.setNotificationChannelAsync(CHANNEL, {
      name: t('Safety reminders'),
      description: t('Short tips to help you spot scams. Nothing personal is ever in them.'),
      importance: Notifications.AndroidImportance.DEFAULT,
    });
  }
  const current = await Notifications.getPermissionsAsync();
  if (current.granted) return true;
  if (!current.canAskAgain) return false;
  return (await Notifications.requestPermissionsAsync()).granted;
}

/** Cancels every reminder this app scheduled. */
export async function cancelReminders() {
  if (Platform.OS === 'web') return;
  await Notifications.cancelAllScheduledNotificationsAsync();
}

/** Replaces the schedule with the next two weeks of reminders, in the app's current language. */
export async function scheduleReminders(now = new Date()) {
  if (Platform.OS === 'web') return 0;
  await cancelReminders();
  if (!getSettings().reminders || !(await permissionGranted())) return 0;
  if (Platform.OS === 'android') {
    await Notifications.setNotificationChannelAsync(CHANNEL, {
      name: t('Safety reminders'),
      description: t('Short tips to help you spot scams. Nothing personal is ever in them.'),
      importance: Notifications.AndroidImportance.DEFAULT,
    });
  }
  const pool = messages();
  const dayNumber = Math.floor(now.getTime() / 86_400_000);
  let count = 0;
  for (let day = 0; day < DAYS; day++) {
    for (const hour of HOURS) {
      const when = new Date(now.getFullYear(), now.getMonth(), now.getDate() + day, hour, 0, 0, 0);
      if (when.getTime() <= now.getTime() + 60_000) continue;
      const list = pool[hour];
      const message = list[(dayNumber + day) % list.length];
      await Notifications.scheduleNotificationAsync({
        content: { title: message.title, body: message.body, data: { route: message.route }, sound: false },
        trigger: { type: Notifications.SchedulableTriggerInputTypes.DATE, date: when, channelId: CHANNEL },
      });
      count++;
    }
  }
  return count;
}

/** Turns reminders on (asking permission) or off; returns whether they are on afterwards. */
export async function setReminders(on: boolean) {
  if (!on) {
    updateSettings({ reminders: false, remindersAsked: true });
    await cancelReminders();
    return false;
  }
  const granted = await askPermission();
  updateSettings({ reminders: granted, remindersAsked: true });
  if (granted) await scheduleReminders();
  return granted;
}
