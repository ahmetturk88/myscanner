import { DMSans_400Regular, DMSans_500Medium, DMSans_600SemiBold, DMSans_700Bold, DMSans_800ExtraBold } from '@expo-google-fonts/dm-sans';
import { SpaceMono_400Regular, SpaceMono_700Bold } from '@expo-google-fonts/space-mono';
import { useFonts } from 'expo-font';
import { DarkTheme, Stack, ThemeProvider } from 'expo-router';
import * as SplashScreen from 'expo-splash-screen';
import { StatusBar } from 'expo-status-bar';
import { useEffect } from 'react';

import { AuthProvider, useAuth } from '@/lib/auth';
import { colors } from '@/lib/theme';

SplashScreen.preventAutoHideAsync();

const theme = {
  ...DarkTheme,
  colors: { ...DarkTheme.colors, background: colors.bg, card: colors.bg, text: colors.text, border: colors.line, primary: colors.cyan },
};

function Navigator() {
  const { ready, user } = useAuth();
  const [fontsLoaded, fontError] = useFonts({
    DMSans_400Regular, DMSans_500Medium, DMSans_600SemiBold, DMSans_700Bold, DMSans_800ExtraBold, SpaceMono_400Regular, SpaceMono_700Bold,
  });
  const loaded = ready && (fontsLoaded || !!fontError);
  useEffect(() => {
    if (loaded) SplashScreen.hideAsync();
  }, [loaded]);
  if (!loaded) return null;
  return (
    <Stack screenOptions={{ headerShown: false, contentStyle: { backgroundColor: colors.bg }, animation: 'slide_from_right' }}>
      <Stack.Protected guard={!!user}>
        <Stack.Screen name="(tabs)" />
        <Stack.Screen name="scan/[id]" />
        <Stack.Screen name="tool/[name]" />
        <Stack.Screen name="file" />
        <Stack.Screen name="qr" options={{ animation: 'slide_from_bottom' }} />
        <Stack.Screen name="delete-account" />
      </Stack.Protected>
      <Stack.Protected guard={!user}>
        <Stack.Screen name="login" options={{ animation: 'fade' }} />
      </Stack.Protected>
    </Stack>
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
