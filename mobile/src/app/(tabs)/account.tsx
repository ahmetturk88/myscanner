import { router, useFocusEffect } from 'expo-router';
import * as WebBrowser from 'expo-web-browser';
import { useCallback } from 'react';
import { Text, View } from 'react-native';

import { Button, Card, Muted, Screen, Title } from '@/components/ui';
import { SITE } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { colors } from '@/lib/theme';

export default function Account() {
  const { user, signOut, refresh } = useAuth();
  useFocusEffect(useCallback(() => { refresh().catch(() => {}); }, [refresh]));
  if (!user) return null;
  return (
    <Screen>
      <Title kicker="ACCOUNT" sub={user.email}>{user.username}</Title>
      <Card>
        <Text style={{ color: colors.text, fontSize: 17, fontWeight: '800' }}>{"Today's allowance"}</Text>
        <Muted>Resets every day at 00:00 UTC.</Muted>
        {user.allowance.map((row) => (
          <View key={row.service} style={{ flexDirection: 'row', justifyContent: 'space-between', paddingVertical: 4 }}>
            <Text style={{ color: colors.text, fontSize: 15 }}>{row.label}</Text>
            <Text style={{ color: row.remaining === 0 ? colors.amber : colors.cyan, fontSize: 15, fontWeight: '700' }}>
              {row.limit === null ? 'Unlimited' : `${row.remaining} / ${row.limit}`}
            </Text>
          </View>
        ))}
      </Card>
      <Card>
        <Button label="Privacy policy" kind="secondary" onPress={() => WebBrowser.openBrowserAsync(`${SITE}/privacy`)} />
        <Button label="Terms of service" kind="secondary" onPress={() => WebBrowser.openBrowserAsync(`${SITE}/terms`)} />
        <Button label="Contact and feedback" kind="secondary" onPress={() => WebBrowser.openBrowserAsync(`${SITE}/contact`)} />
      </Card>
      <Button label="Sign out" kind="secondary" onPress={signOut} />
      <Button label="Delete account…" kind="danger" onPress={() => router.push('/delete-account')} />
    </Screen>
  );
}
