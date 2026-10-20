import Constants from 'expo-constants';
import { LinearGradient } from 'expo-linear-gradient';
import { router, useFocusEffect } from 'expo-router';
import * as WebBrowser from 'expo-web-browser';
import { useCallback, useState } from 'react';
import { StyleSheet, Text, View } from 'react-native';
import Animated from 'react-native-reanimated';

import { Icon, type IconName } from '@/components/icon';
import { Bar, enter, PressableScale, Spin, useCountUp } from '@/components/motion';
import { Screen } from '@/components/screen';
import { api, SITE } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { t, upper } from '@/lib/i18n';
import { colors, fonts, gradients, tone } from '@/lib/theme';

function Stat({ label, value, color, icon, index }: { label: string; value?: number; color: string; icon: IconName; index: number }) {
  const n = useCountUp(value);
  return (
    <Animated.View entering={enter(index)} style={s.stat}>
      <View style={[s.statIcon, { backgroundColor: color + '14', borderColor: color + '40' }]}><Icon name={icon} size={16} color={color} /></View>
      <Text style={{ color: colors.text, fontSize: 24, fontFamily: fonts.bold }}>{n ?? '—'}</Text>
      <Text style={{ color: colors.muted, fontSize: 12.5, fontFamily: fonts.medium }}>{label}</Text>
    </Animated.View>
  );
}

function Row({ icon, label, onPress, danger, last }: { icon: IconName; label: string; onPress: () => void; danger?: boolean; last?: boolean }) {
  return (
    <PressableScale scale={0.98} onPress={onPress} style={[s.row, !last && s.rowLine]}>
      <View style={[s.rowIcon, danger && { backgroundColor: 'rgba(251,113,133,.1)', borderColor: 'rgba(251,113,133,.3)' }]}>
        <Icon name={icon} size={17} color={danger ? colors.red : colors.cyan} />
      </View>
      <Text style={{ flex: 1, color: danger ? colors.red : colors.text, fontSize: 15, fontFamily: fonts.medium }}>{label}</Text>
      <Icon name="chevron" size={16} color={colors.faint} />
    </PressableScale>
  );
}

export default function Account() {
  const { user, signOut, refresh } = useAuth();
  const [scans, setScans] = useState<{ verdict: string }[] | null>(null);
  const load = useCallback(() => Promise.all([
    refresh().catch(() => {}),
    api.recent().then((d) => setScans(d.scans)).catch(() => {}),
  ]), [refresh]);
  useFocusEffect(useCallback(() => { load(); }, [load]));
  if (!user) return null;
  const open = (path: string) => WebBrowser.openBrowserAsync(`${SITE}${path}`);
  const count = (level: string) => scans?.filter((x) => tone(x.verdict) === level).length;

  return (
    <Screen tabs title={t('Account')} onRefresh={load}>
      <Animated.View entering={enter(0)} style={s.profile}>
        <View style={{ width: 92, height: 92, alignItems: 'center', justifyContent: 'center' }}>
          <View style={StyleSheet.absoluteFill}>
            <Spin><LinearGradient colors={['#38bdf8', '#5eead4', '#a78bfa', '#38bdf8']} style={{ width: 92, height: 92, borderRadius: 46 }} /></Spin>
          </View>
          <View style={s.avatar}><Text style={{ color: '#fff', fontSize: 34, fontFamily: fonts.bold }}>{user.username[0].toUpperCase()}</Text></View>
        </View>
        <Text style={{ color: colors.text, fontSize: 23, fontFamily: fonts.bold, marginTop: 6 }}>{user.username}</Text>
        <Text style={{ color: colors.soft, fontSize: 14, fontFamily: fonts.regular }}>{user.email}</Text>
        <View style={{ flexDirection: 'row', gap: 8, marginTop: 4 }}>
          <View style={[s.tag, { borderColor: 'rgba(74,222,128,.4)', backgroundColor: 'rgba(74,222,128,.07)' }]}>
            <Text style={{ color: '#86efac', fontSize: 10.5, letterSpacing: 1, fontFamily: fonts.monoBold }}>{t('✓ VERIFIED')}</Text>
          </View>
          <View style={s.tag}>
            <Text style={{ color: colors.soft, fontSize: 10.5, letterSpacing: 1, fontFamily: fonts.monoBold }}>{user.role === 'user' ? t('FREE PLAN') : upper(user.role)}</Text>
          </View>
        </View>
      </Animated.View>

      <View style={{ flexDirection: 'row', flexWrap: 'wrap', gap: 10 }}>
        <Stat index={1} label={t('Reports')} value={scans?.length} color={colors.cyan} icon="clock" />
        <Stat index={2} label={t('Threats')} value={count('risk')} color={colors.red} icon="alert" />
        <Stat index={3} label={t('To review')} value={count('review')} color={colors.amber} icon="search" />
        <Stat index={4} label={t('Clean')} value={count('safe')} color={colors.green} icon="check" />
      </View>

      <Animated.View entering={enter(5)} style={s.card}>
        <View style={{ flexDirection: 'row', alignItems: 'center' }}>
          <Text style={s.cardTitle}>{t('Daily allowance')}</Text>
          <Text style={{ marginLeft: 'auto', color: colors.faint, fontSize: 12, fontFamily: fonts.regular }}>{t('Resets 00:00 UTC')}</Text>
        </View>
        {user.allowance.map((row, i) => {
          const low = row.limit !== null && (row.remaining ?? 0) === 0;
          return (
            <View key={row.service} style={{ gap: 7 }}>
              <View style={{ flexDirection: 'row', justifyContent: 'space-between' }}>
                <Text style={{ color: colors.soft, fontSize: 14, fontFamily: fonts.regular }}>{row.label}</Text>
                <Text style={{ color: low ? colors.amber : colors.cyan, fontSize: 13, fontFamily: fonts.monoBold }}>
                  {row.limit === null ? t('Unlimited') : `${row.remaining} / ${row.limit}`}
                </Text>
              </View>
              <Bar percent={row.limit === null ? 100 : row.percent} colors={low ? [colors.amber, colors.amber] : gradients.accent} delay={300 + i * 90} />
            </View>
          );
        })}
      </Animated.View>

      <Animated.View entering={enter(6)} style={[s.card, { paddingVertical: 4, gap: 0 }]}>
        <Row icon="settings" label={t('Settings')} onPress={() => router.push('/settings')} />
        <Row icon="mail" label={t('Contact and feedback')} onPress={() => open('/contact')} last />
      </Animated.View>
      <Animated.View entering={enter(7)} style={[s.card, { paddingVertical: 4, gap: 0 }]}>
        <Row icon="logout" label={t('Sign out')} onPress={signOut} />
        <Row icon="trash" label={t('Delete account')} onPress={() => router.push('/delete-account')} danger last />
      </Animated.View>
      <Text style={{ color: colors.faint, fontSize: 12, textAlign: 'center', fontFamily: fonts.mono }}>
        MyScanner {Constants.expoConfig?.version ?? ''}
      </Text>
    </Screen>
  );
}

const s = StyleSheet.create({
  profile: { alignItems: 'center', gap: 4, paddingVertical: 22, borderRadius: 26, borderWidth: 1, borderColor: colors.line, backgroundColor: 'rgba(14,24,37,.85)' },
  avatar: { width: 84, height: 84, borderRadius: 42, backgroundColor: '#0d1726', alignItems: 'center', justifyContent: 'center' },
  tag: { paddingVertical: 4, paddingHorizontal: 10, borderRadius: 999, borderWidth: 1, borderColor: colors.line },
  stat: { width: '48%', flexGrow: 1, padding: 14, borderRadius: 20, borderWidth: 1, borderColor: colors.line, backgroundColor: '#0e1825', gap: 4 },
  statIcon: { width: 32, height: 32, borderRadius: 10, alignItems: 'center', justifyContent: 'center', borderWidth: 1, marginBottom: 4 },
  card: { padding: 18, borderRadius: 22, borderWidth: 1, borderColor: colors.line, backgroundColor: '#0e1825', gap: 14 },
  cardTitle: { color: colors.text, fontSize: 16, fontFamily: fonts.bold },
  row: { flexDirection: 'row', alignItems: 'center', gap: 12, paddingVertical: 13 },
  rowLine: { borderBottomWidth: 1, borderBottomColor: 'rgba(145,188,220,.1)' },
  rowIcon: { width: 34, height: 34, borderRadius: 11, alignItems: 'center', justifyContent: 'center', backgroundColor: 'rgba(119,220,255,.07)', borderWidth: 1, borderColor: 'rgba(119,220,255,.2)' },
});
