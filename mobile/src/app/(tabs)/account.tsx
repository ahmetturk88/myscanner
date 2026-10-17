import { LinearGradient } from 'expo-linear-gradient';
import { router, useFocusEffect } from 'expo-router';
import * as WebBrowser from 'expo-web-browser';
import { useCallback, useState } from 'react';
import { Pressable, Text, View } from 'react-native';

import { Icon, type IconName } from '@/components/icon';
import { Appear } from '@/components/motion';
import { Page } from '@/components/site';
import { Button, Card, Eyebrow, Muted } from '@/components/ui';
import { api, SITE } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { colors, fonts, gradients, tone } from '@/lib/theme';

function Stat({ label, value, note, color, icon }: { label: string; value?: number; note: string; color: string; icon: IconName }) {
  return (
    <View style={{ flex: 1, minWidth: '45%', padding: 14, borderRadius: 16, borderWidth: 1, borderColor: colors.line, backgroundColor: '#0f1a29', gap: 6 }}>
      <View style={{ flexDirection: 'row', justifyContent: 'space-between' }}>
        <Text style={{ color: colors.soft, fontSize: 13.5, fontFamily: fonts.medium }}>{label}</Text>
        <Icon name={icon} size={17} color={color} />
      </View>
      <Text style={{ color, fontSize: 26, fontFamily: fonts.bold }}>{value ?? '—'}</Text>
      <Text style={{ color: colors.faint, fontSize: 12, fontFamily: fonts.regular }}>{note}</Text>
    </View>
  );
}

function Row({ icon, label, onPress, danger }: { icon: IconName; label: string; onPress: () => void; danger?: boolean }) {
  return (
    <Pressable accessibilityRole="button" onPress={onPress}
      style={({ pressed }) => ({ flexDirection: 'row', alignItems: 'center', gap: 12, paddingVertical: 13, opacity: pressed ? 0.6 : 1 })}>
      <Icon name={icon} size={19} color={danger ? colors.red : colors.cyan} />
      <Text style={{ flex: 1, color: danger ? colors.red : colors.text, fontSize: 15, fontFamily: fonts.medium }}>{label}</Text>
      <Icon name="chevron" size={17} color={colors.faint} />
    </Pressable>
  );
}

export default function Account() {
  const { user, signOut, refresh } = useAuth();
  const [scans, setScans] = useState<{ verdict: string }[] | null>(null);
  useFocusEffect(useCallback(() => {
    refresh().catch(() => {});
    api.recent().then((d) => setScans(d.scans)).catch(() => {});
  }, [refresh]));
  if (!user) return null;
  const open = (path: string) => WebBrowser.openBrowserAsync(`${SITE}${path}`);
  const count = (t: string) => scans?.filter((s) => tone(s.verdict) === t).length;
  return (
    <Page>
      <Appear>
        <Card style={{ alignItems: 'center', paddingVertical: 26 }}>
          <LinearGradient colors={['#38bdf8', '#a78bfa']} style={{ width: 84, height: 84, borderRadius: 42, padding: 3 }}>
            <View style={{ flex: 1, borderRadius: 40, backgroundColor: '#0d1726', alignItems: 'center', justifyContent: 'center' }}>
              <Text style={{ color: '#fff', fontSize: 32, fontFamily: fonts.bold }}>{user.username[0].toUpperCase()}</Text>
            </View>
          </LinearGradient>
          <Eyebrow color={colors.teal}>Your account</Eyebrow>
          <Text style={{ color: colors.text, fontSize: 24, fontFamily: fonts.bold, marginTop: -6 }}>{user.username}</Text>
          <Text style={{ color: colors.soft, fontSize: 14, fontFamily: fonts.regular }}>{user.email}</Text>
          <View style={{ flexDirection: 'row', gap: 8 }}>
            <View style={{ paddingVertical: 4, paddingHorizontal: 10, borderRadius: 999, borderWidth: 1, borderColor: 'rgba(74,222,128,.4)' }}>
              <Text style={{ color: '#86efac', fontSize: 11, letterSpacing: 1, fontFamily: fonts.monoBold }}>✓ EMAIL VERIFIED</Text>
            </View>
            <View style={{ paddingVertical: 4, paddingHorizontal: 10, borderRadius: 999, borderWidth: 1, borderColor: colors.line }}>
              <Text style={{ color: colors.soft, fontSize: 11, letterSpacing: 1, fontFamily: fonts.monoBold }}>{user.role === 'user' ? 'FREE PLAN' : user.role.toUpperCase()}</Text>
            </View>
          </View>
          <View style={{ flexDirection: 'row', gap: 10, marginTop: 4 }}>
            <Button label="New scan" icon="bolt" onPress={() => router.navigate('/')} />
            <Button kind="secondary" label="Workspace" onPress={() => router.navigate('/history')} />
          </View>
        </Card>
      </Appear>
      <View style={{ flexDirection: 'row', flexWrap: 'wrap', gap: 10 }}>
        <Stat label="URL scans" value={scans?.length} note="Recent reports" color={colors.cyan} icon="clock" />
        <Stat label="Confirmed threats" value={count('risk')} note="Backed by a reputation source" color={colors.red} icon="alert" />
        <Stat label="Needs review" value={count('review')} note="Indicators without confirmation" color={colors.amber} icon="search" />
        <Stat label="No indicators" value={count('safe')} note="Full coverage, nothing found" color={colors.green} icon="check" />
      </View>
      <Card>
        <Eyebrow>Daily allowance</Eyebrow>
        <Muted>Resets every day at 00:00 UTC.</Muted>
        {user.allowance.map((row) => {
          const percent = row.limit === null ? 100 : row.percent;
          const low = row.limit !== null && (row.remaining ?? 0) === 0;
          return (
            <View key={row.service} style={{ gap: 6 }}>
              <View style={{ flexDirection: 'row', justifyContent: 'space-between' }}>
                <Text style={{ color: colors.soft, fontSize: 14, fontFamily: fonts.regular }}>{row.label}</Text>
                <Text style={{ color: low ? colors.amber : colors.cyan, fontSize: 13.5, fontFamily: fonts.monoBold }}>
                  {row.limit === null ? 'Unlimited' : `${row.remaining} / ${row.limit}`}
                </Text>
              </View>
              <View style={{ height: 5, borderRadius: 5, backgroundColor: '#152338', overflow: 'hidden' }}>
                <LinearGradient colors={low ? [colors.amber, colors.amber] : gradients.accent} start={{ x: 0, y: 0 }} end={{ x: 1, y: 0 }}
                  style={{ width: `${Math.max(3, percent)}%`, height: '100%' }} />
              </View>
            </View>
          );
        })}
      </Card>
      <Card style={{ gap: 0, paddingVertical: 6 }}>
        <Row icon="shield" label="Privacy policy" onPress={() => open('/privacy')} />
        <Row icon="doc" label="Terms of service" onPress={() => open('/terms')} />
        <Row icon="mail" label="Contact and feedback" onPress={() => open('/contact')} />
        <Row icon="logout" label="Sign out" onPress={signOut} />
        <Row icon="trash" label="Delete account" onPress={() => router.push('/delete-account')} danger />
      </Card>
    </Page>
  );
}
