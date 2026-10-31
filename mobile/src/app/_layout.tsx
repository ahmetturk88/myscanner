import { DMSans_400Regular, DMSans_500Medium, DMSans_600SemiBold, DMSans_700Bold, DMSans_800ExtraBold } from '@expo-google-fonts/dm-sans';
import { SpaceMono_400Regular, SpaceMono_700Bold } from '@expo-google-fonts/space-mono';
import { useFonts } from 'expo-font';
import * as Notifications from 'expo-notifications';
import { DarkTheme, router, Stack, ThemeProvider } from 'expo-router';
import * as SplashScreen from 'expo-splash-screen';
import { StatusBar } from 'expo-status-bar';
import { useEffect, useRef, useState } from 'react';
import { AppState, Platform } from 'react-native';

import { ReminderPrompt } from '@/components/reminder-prompt';
import { UpdateCard, UpdateRequired } from '@/components/update-prompt';
import { AuthProvider, useAuth } from '@/lib/auth';
import { reminderRoute, scheduleReminders } from '@/lib/reminders';
import { loadSettings, useSettings, useSettingsReady } from '@/lib/settings';
import { colors } from '@/lib/theme';
import { useAppUpdate } from '@/lib/update';

SplashScreen.preventAutoHideAsync();
loadSettings();
// A reminder that arrives while MyScanner is open stays in the tray instead of covering the screen.
if (Platform.OS !== 'web') {
  Notifications.setNotificationHandler({
    handleNotification: async () => ({ shouldShowBanner: false, shouldShowList: true, shouldPlaySound: false, shouldSetBadge: false }),
  });
}

/** Opens the screen a tapped reminder names, only if it is one of ours and someone is signed in. */
function openReminder(response: Notifications.NotificationResponse | null, signedIn: boolean) {
  const route = reminderRoute(response?.notification.request.content.data?.route);
  if (route && signedIn && route !== '/') router.push(route);
}

const theme = {
  ...DarkTheme,
  colors: { ...DarkTheme.colors, background: colors.bg, card: colors.bg, text: colors.text, border: colors.line, primary: colors.cyan },
};

function Navigator() {
  const { ready, user } = useAuth();
  const settingsReady = useSettingsReady();
  const { language } = useSettings();
  const [fontsLoaded, fontError] = useFonts({
    DMSans_400Regular, DMSans_500Medium, DMSans_600SemiBold, DMSans_700Bold, DMSans_800ExtraBold, SpaceMono_400Regular, SpaceMono_700Bold,
  });
  const appUpdate = useAppUpdate();
  const { reminders, remindersAsked } = useSettings();
  const [offer, setOffer] = useState(false);
  const lastResponse = Notifications.useLastNotificationResponse();
  const handled = useRef<string | null>(null);
  const loaded = ready && settingsReady && (fontsLoaded || !!fontError);
  useEffect(() => {
    if (loaded) SplashScreen.hideAsync();
  }, [loaded]);
  // The reminders card, once, a moment after sign-in; never on top of an update prompt.
  useEffect(() => {
    if (!loaded || !user || remindersAsked || Platform.OS === 'web' || appUpdate.kind !== 'none') return;
    const timer = setTimeout(() => setOffer(true), 1800);
    return () => clearTimeout(timer);
  }, [loaded, user, remindersAsked, appUpdate.kind]);
  // The next two weeks of reminders, in the current language, each time the app opens or comes back.
  useEffect(() => {
    if (!loaded || !reminders || Platform.OS === 'web') return;
    scheduleReminders().catch(() => {});
    const sub = AppState.addEventListener('change', (state) => { if (state === 'active') scheduleReminders().catch(() => {}); });
    return () => sub.remove();
  }, [loaded, reminders, language]);
  useEffect(() => {
    // Each tapped reminder opens its screen once, even if the user signs in again later.
    const id = lastResponse?.notification.request.identifier ?? null;
    if (!loaded || !lastResponse || !user || handled.current === id) return;
    handled.current = id;
    openReminder(lastResponse, true);
  }, [loaded, lastResponse, user]);
  if (!loaded) return null;
  if (appUpdate.kind === 'required') return <UpdateRequired onUpdate={appUpdate.update} />;
  // Keyed by language: picking another language remounts every screen, so all text is drawn again in it.
  return (
    <>
      <Stack key={language} screenOptions={{ headerShown: false, contentStyle: { backgroundColor: colors.bg }, animation: 'slide_from_right' }}>
        <Stack.Protected guard={!!user}>
          <Stack.Screen name="(tabs)" />
          <Stack.Screen name="scan/[id]" />
          <Stack.Screen name="tool/[name]" />
          <Stack.Screen name="file" />
          <Stack.Screen name="qr" options={{ animation: 'slide_from_bottom' }} />
          <Stack.Screen name="delete-account" />
          <Stack.Screen name="settings" />
        </Stack.Protected>
        <Stack.Protected guard={!user}>
          <Stack.Screen name="login" options={{ animation: 'fade' }} />
        </Stack.Protected>
      </Stack>
      {appUpdate.kind === 'available' ? <UpdateCard onUpdate={appUpdate.update} onLater={appUpdate.later} /> : null}
      {offer && user && !remindersAsked ? <ReminderPrompt onDone={() => setOffer(false)} /> : null}
    </>
  );
}

export default function RootLayout() {
  return (
    <ThemeProvider value={theme}>
      <AuthProvider>
        <StatusBar style="light" />
        <Navigator />
      </AuthProvider>
    </ThemeProvider>
  );
}
