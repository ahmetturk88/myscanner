import { LinearGradient } from 'expo-linear-gradient';
import { router, useFocusEffect } from 'expo-router';
import * as WebBrowser from 'expo-web-browser';
import { useCallback } from 'react';
import { Pressable, Text, View } from 'react-native';

import { TAB_BAR_SPACE } from '@/components/app-tabs';
import { Icon, type IconName } from '@/components/icon';
import { Appear } from '@/components/motion';
import { Card, Muted, Screen, Section } from '@/components/ui';
import { SITE } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { colors, gradients } from '@/lib/theme';

function Row({ icon, label, onPress, danger }: { icon: IconName; label: string; onPress: () => void; danger?: boolean }) {
  return (
    <Pressable accessibilityRole="button" onPress={onPress}
      style={({ pressed }) => ({ flexDirection: 'row', alignItems: 'center', gap: 12, paddingVertical: 13, opacity: pressed ? 0.6 : 1 })}>
      <Icon name={icon} size={20} color={danger ? colors.red : colors.cyanSoft} />
      <Text style={{ flex: 1, color: danger ? colors.red : colors.text, fontSize: 15.5, fontWeight: '600' }}>{label}</Text>
      <Icon name="chevron" size={18} color={colors.faint} />
    </Pressable>
  );
}

export default function Account() {
  const { user, signOut, refresh } = useAuth();
  useFocusEffect(useCallback(() => { refresh().catch(() => {}); }, [refresh]));
  if (!user) return null;
  const open = (path: string) => WebBrowser.openBrowserAsync(`${SITE}${path}`);
  return (
    <Screen bottom={TAB_BAR_SPACE}>
      <Appear>
        <View style={{ alignItems: 'center', gap: 8, marginTop: 10 }}>
          <LinearGradient colors={['#1f6f99', '#6d28d9']} style={{ width: 82, height: 82, borderRadius: 41, alignItems: 'center', justifyContent: 'center' }}>
            <Text style={{ color: '#fff', fontSize: 34, fontWeight: '800' }}>{user.username[0].toUpperCase()}</Text>
          </LinearGradient>
          <Text style={{ color: colors.text, fontSize: 23, fontWeight: '800' }}>{user.username}</Text>
          <Text style={{ color: colors.muted }}>{user.email}</Text>
          {user.role !== 'user' ? (
            <LinearGradient colors={gradients.accent} style={{ borderRadius: 999, paddingVertical: 4, paddingHorizontal: 12 }}>
              <Text style={{ color: colors.onAccent, fontWeight: '800', fontSize: 12 }}>{user.role.toUpperCase()}</Text>
            </LinearGradient>
          ) : null}
        </View>
      </Appear>
      <Appear delay={100}>
        <View style={{ gap: 10 }}>
          <Section>{"Today's allowance"}</Section>
          <Card>
            <Muted>Resets every day at 00:00 UTC.</Muted>
            {user.allowance.map((row) => {
              const percent = row.limit === null ? 100 : row.percent;
              const low = row.limit !== null && (row.remaining ?? 0) === 0;
              return (
                <View key={row.service} style={{ gap: 6 }}>
                  <View style={{ flexDirection: 'row', justifyContent: 'space-between' }}>
                    <Text style={{ color: colors.soft, fontSize: 14.5 }}>{row.label}</Text>
                    <Text style={{ color: low ? colors.amber : colors.cyanSoft, fontSize: 14, fontWeight: '800' }}>
                      {row.limit === null ? 'Unlimited' : `${row.remaining} / ${row.limit}`}
                    </Text>
                  </View>
                  <View style={{ height: 6, borderRadius: 6, backgroundColor: '#152338', overflow: 'hidden' }}>
                    <LinearGradient colors={low ? [colors.amber, colors.amber] : gradients.accent} start={{ x: 0, y: 0 }} end={{ x: 1, y: 0 }}
                      style={{ width: `${Math.max(3, percent)}%`, height: '100%', borderRadius: 6 }} />
                  </View>
                </View>
              );
            })}
          </Card>
        </View>
      </Appear>
      <Appear delay={180}>
        <Card style={{ gap: 0, paddingVertical: 4 }}>
          <Row icon="shield" label="Privacy policy" onPress={() => open('/privacy')} />
          <Row icon="doc" label="Terms of service" onPress={() => open('/terms')} />
          <Row icon="mail" label="Contact and feedback" onPress={() => open('/contact')} />
          <Row icon="globe" label="Open myscanners.com" onPress={() => open('/')} />
        </Card>
      </Appear>
      <Card style={{ gap: 0, paddingVertical: 4 }}>
        <Row icon="logout" label="Sign out" onPress={signOut} />
        <Row icon="trash" label="Delete account" onPress={() => router.push('/delete-account')} danger />
      </Card>
      <Text style={{ color: colors.faint, fontSize: 12, textAlign: 'center' }}>MyScanner for Android · version 0.2</Text>
    </Screen>
  );
}
