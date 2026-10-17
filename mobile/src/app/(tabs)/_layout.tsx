import { Stack } from 'expo-router';

import { colors } from '@/lib/theme';

/** Main pages; navigation is the website's top bar and toolkit menu. */
export default function MainLayout() {
  return <Stack screenOptions={{ headerShown: false, contentStyle: { backgroundColor: colors.bg }, animation: 'fade' }} />;
}
