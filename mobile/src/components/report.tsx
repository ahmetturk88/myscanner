import * as Haptics from 'expo-haptics';
import { Image } from 'expo-image';
import { LinearGradient } from 'expo-linear-gradient';
import { useEffect, useState } from 'react';
import { Share, StyleSheet, Text, View } from 'react-native';
import Animated, {
  Easing, useAnimatedProps, useAnimatedStyle, useSharedValue, withDelay, withRepeat, withSpring, withTiming, ZoomIn,
} from 'react-native-reanimated';
import Svg, { Circle } from 'react-native-svg';

import { Icon, type IconName } from '@/components/icon';
import { enter, PressableScale } from '@/components/motion';
import { Button } from '@/components/ui';
import { colors, fonts } from '@/lib/theme';

/** The plain-language summary every tool returns as `plain` (built on the server). */
export type Plain = {
  tone: string; label: string; headline: string; summary: string;
  url?: { prefix?: string; host?: string; rest?: string };
  reasons?: { tone: string; title: string; detail: string }[];
  actions?: string[];
  checks?: { name: string; state: string; result: string }[];
  tally?: string; share_text?: string; why_title?: string; checked?: string;
};

type HeroTone = 'danger' | 'caution' | 'unknown' | 'safe' | 'info';
type State = 'bad' | 'warn' | 'ok' | 'na' | 'info';

const HERO: Record<HeroTone, { color: string; icon: IconName }> = {
  danger: { color: colors.red, icon: 'shieldX' },
  caution: { color: colors.amber, icon: 'alert' },
  unknown: { color: colors.muted, icon: 'question' },
  safe: { color: colors.green, icon: 'shieldCheck' },
  info: { color: colors.cyan, icon: 'target' },
};
const STATE: Record<State, { color: string; icon: IconName }> = {
  bad: { color: colors.red, icon: 'xCircle' },
  warn: { color: colors.amber, icon: 'alert' },
  ok: { color: colors.green, icon: 'checkCircle' },
  na: { color: colors.faint, icon: 'minusCircle' },
  info: { color: colors.cyan, icon: 'info' },
};
const ORDER: State[] = ['bad', 'warn', 'ok', 'info', 'na'];

const heroTone = (t: unknown): HeroTone => (typeof t === 'string' && t in HERO ? t as HeroTone : 'unknown');
const state = (s: unknown): State => (typeof s === 'string' && s in STATE ? s as State : 'na');
const objects = <T,>(v: unknown): T[] => (Array.isArray(v) ? v.filter((x) => x && typeof x === 'object') : []);
const str = (v: unknown) => (typeof v === 'string' ? v : '');

/** True when a tool result carries a summary this screen can draw. */
export function hasPlain(value: any): value is Plain {
  return !!value && typeof value === 'object' && !Array.isArray(value) && typeof value.headline === 'string';
}

/** The evidence below the summary: everything except the summary itself. */
export function withoutPlain(result: Record<string, unknown>) {
  const { plain: _plain, ...rest } = result;
  return rest;
}

const AnimatedCircle = Animated.createAnimatedComponent(Circle);

/** A soft ring that keeps spreading out from the mark while the verdict is a warning. */
function Halo({ size, color, offset }: { size: number; color: string; offset: number }) {
  const t = useSharedValue(0);
  useEffect(() => { t.value = withDelay(offset, withRepeat(withTiming(1, { duration: 2400, easing: Easing.out(Easing.quad) }), -1)); }, [t, offset]);
  const style = useAnimatedStyle(() => ({ opacity: 0.55 * (1 - t.value), transform: [{ scale: 1 + 0.45 * t.value }] }));
  return <Animated.View pointerEvents="none" style={[{ position: 'absolute', width: size, height: size, borderRadius: size / 2, borderWidth: 2, borderColor: color }, style]} />;
}

/** The verdict mark: a ring that draws itself, then the icon springs in. */
function Seal({ tone }: { tone: HeroTone }) {
  const { color, icon } = HERO[tone];
  const size = 96, r = 44, length = 2 * Math.PI * r;
  const draw = useSharedValue(0);
  const pop = useSharedValue(0);
  useEffect(() => {
    draw.value = withDelay(150, withTiming(1, { duration: 900, easing: Easing.out(Easing.cubic) }));
    pop.value = withDelay(500, withSpring(1, { damping: 9, stiffness: 140 }));
  }, [draw, pop]);
  const props = useAnimatedProps(() => ({ strokeDashoffset: length * (1 - draw.value) }));
  const iconStyle = useAnimatedStyle(() => ({ opacity: Math.min(1, pop.value * 1.5), transform: [{ scale: 0.4 + 0.6 * pop.value }] }));
  const warn = tone === 'danger' || tone === 'caution';
  return (
    <View style={{ width: size + 24, height: size + 24, alignItems: 'center', justifyContent: 'center' }}>
      {warn ? <><Halo size={size} color={color} offset={0} /><Halo size={size} color={color} offset={1200} /></> : null}
      <Svg width={size} height={size} viewBox="0 0 96 96" style={{ position: 'absolute' }}>
        <Circle cx={48} cy={48} r={r} stroke={color + '26'} strokeWidth={5} fill={color + '12'} />
        <AnimatedCircle cx={48} cy={48} r={r} stroke={color} strokeWidth={5} fill="none" strokeLinecap="round"
          strokeDasharray={`${length} ${length}`} animatedProps={props} transform="rotate(-90 48 48)" />
      </Svg>
      <Animated.View style={iconStyle}><Icon name={icon} size={42} color={color} stroke={1.8} /></Animated.View>
    </View>
  );
}

function Hero({ plain, tone }: { plain: Plain; tone: HeroTone }) {
  const { color } = HERO[tone];
  const target = plain.url && typeof plain.url === 'object' ? plain.url : {};
  const host = str(target.host);
  return (
    <Animated.View entering={enter(0)} style={[s.hero, { borderColor: color + '55' }]}>
      <LinearGradient colors={[color + '2e', color + '08', 'rgba(14,24,37,0)']} start={{ x: 0.5, y: 0 }} end={{ x: 0.5, y: 1 }} style={StyleSheet.absoluteFill} />
      <Seal tone={tone} />
      <Animated.View entering={ZoomIn.delay(300).springify()} style={[s.label, { borderColor: color + '66', backgroundColor: color + '18' }]}>
        <View style={{ width: 7, height: 7, borderRadius: 4, backgroundColor: color }} />
        <Text style={{ color, fontSize: 12, fontFamily: fonts.monoBold, letterSpacing: 1.6 }}>{str(plain.label)}</Text>
      </Animated.View>
      <Text accessibilityRole="header" style={s.headline}>{str(plain.headline)}</Text>
      {plain.summary ? <Text style={s.summary}>{plain.summary}</Text> : null}
      {host || target.prefix || target.rest ? (
        <View style={s.target}>
          <Text selectable numberOfLines={3} style={{ color: colors.faint, fontSize: 13.5, fontFamily: fonts.regular, textAlign: 'center' }}>
            {str(target.prefix)}<Text style={{ color: colors.text, fontFamily: fonts.bold }}>{host}</Text>{str(target.rest)}
          </Text>
        </View>
      ) : null}
      {plain.checked ? <Text style={{ color: colors.faint, fontSize: 12, fontFamily: fonts.mono }}>{plain.checked}</Text> : null}
    </Animated.View>
  );
}

function SectionTitle({ children, right }: { children: string; right?: string }) {
  return (
    <View style={{ gap: 3 }}>
      <Text style={s.section}>{children}</Text>
      {right ? <Text style={{ color: colors.faint, fontSize: 12.5, fontFamily: fonts.mono }}>{right}</Text> : null}
    </View>
  );
}

function Reasons({ plain, start }: { plain: Plain; start: number }) {
  const reasons = objects<NonNullable<Plain['reasons']>[number]>(plain.reasons);
  if (!reasons.length) return null;
  return (
    <View style={{ gap: 10 }}>
      <Animated.View entering={enter(start)}><SectionTitle>{str(plain.why_title) || 'Why we think so'}</SectionTitle></Animated.View>
      {reasons.map((r, i) => {
        const look = STATE[state(r.tone)];
        return (
          <Animated.View key={`${r.title}-${i}`} entering={enter(start + i + 1)} style={[s.reason, { borderLeftColor: look.color }]}>
            <View style={[s.dot, { backgroundColor: look.color + '18', borderColor: look.color + '44' }]}>
              <Icon name={look.icon} size={19} color={look.color} />
            </View>
            <View style={{ flex: 1, gap: 4 }}>
              <Text style={{ color: colors.text, fontSize: 15.5, fontFamily: fonts.bold, lineHeight: 21 }}>{str(r.title)}</Text>
              <Text style={{ color: colors.soft, fontSize: 14, lineHeight: 21, fontFamily: fonts.regular }}>{str(r.detail)}</Text>
            </View>
          </Animated.View>
        );
      })}
    </View>
  );
}

function Actions({ plain, tone, start }: { plain: Plain; tone: HeroTone; start: number }) {
  const actions = (Array.isArray(plain.actions) ? plain.actions : []).filter((a) => typeof a === 'string');
  if (!actions.length) return null;
  const { color } = HERO[tone];
  return (
    <Animated.View entering={enter(start)} style={s.card}>
      <SectionTitle>{tone === 'safe' ? 'Good to know' : 'What to do'}</SectionTitle>
      {actions.map((a, i) => (
        <View key={`${i}-${a}`} style={{ flexDirection: 'row', gap: 12, alignItems: 'flex-start' }}>
          <View style={[s.number, { backgroundColor: color + '1f', borderColor: color + '55' }]}>
            <Text style={{ color, fontSize: 13, fontFamily: fonts.monoBold }}>{i + 1}</Text>
          </View>
          <Text style={{ flex: 1, color: colors.text, fontSize: 15, lineHeight: 23, fontFamily: fonts.regular }}>{a}</Text>
        </View>
      ))}
    </Animated.View>
  );
}

/** One coloured segment per state that grows to its share of the checks. */
function Segment({ share, color, delay }: { share: number; color: string; delay: number }) {
  const grow = useSharedValue(0);
  useEffect(() => { grow.value = withDelay(delay, withTiming(share, { duration: 700, easing: Easing.out(Easing.cubic) })); }, [grow, share, delay]);
  const style = useAnimatedStyle(() => ({ flexGrow: grow.value, flexBasis: 0 }));
  return <Animated.View style={[{ height: 8, backgroundColor: color, borderRadius: 4 }, style]} />;
}

function Checks({ plain, start }: { plain: Plain; start: number }) {
  const checks = objects<NonNullable<Plain['checks']>[number]>(plain.checks);
  if (!checks.length) return null;
  const counts = ORDER.map((k) => [k, checks.filter((c) => state(c.state) === k).length] as const).filter(([, n]) => n > 0);
  return (
    <Animated.View entering={enter(start)} style={s.card}>
      <SectionTitle right={str(plain.tally)}>What we checked</SectionTitle>
      <View style={{ flexDirection: 'row', gap: 4 }}>
        {counts.map(([k, n], i) => <Segment key={k} share={n} color={STATE[k].color} delay={300 + i * 120} />)}
      </View>
      <View>
        {checks.map((c, i) => {
          const look = STATE[state(c.state)];
          return (
            <View key={`${c.name}-${i}`} style={[s.check, i === checks.length - 1 && { borderBottomWidth: 0 }]}>
              <Icon name={look.icon} size={18} color={look.color} />
              <Text style={{ flex: 1, color: colors.soft, fontSize: 14.5, fontFamily: fonts.regular }}>{str(c.name)}</Text>
              <Text selectable style={{ maxWidth: '48%', color: look.color, fontSize: 14, fontFamily: fonts.semibold, textAlign: 'right' }}>{str(c.result)}</Text>
            </View>
          );
        })}
      </View>
    </Animated.View>
  );
}

/** The page as our isolated browser saw it; hidden when there is no screenshot. */
function Preview({ source, start }: { source: { uri: string; headers?: Record<string, string> }; start: number }) {
  const [failed, setFailed] = useState(false);
  const [ratio, setRatio] = useState(16 / 10);
  if (failed) return null;
  return (
    <Animated.View entering={enter(start)} style={s.card}>
      <SectionTitle>Page preview</SectionTitle>
      <View style={{ borderRadius: 14, overflow: 'hidden', borderWidth: 1, borderColor: colors.line, backgroundColor: colors.input }}>
        <Image source={source} style={{ width: '100%', aspectRatio: ratio }} contentFit="cover" contentPosition="top" transition={350}
          cachePolicy="none" accessibilityLabel="Screenshot of the scanned page"
          onLoad={(e) => { const { width, height } = e.source; if (width && height) setRatio(Math.max(width / height, 0.75)); }}
          onError={() => setFailed(true)} />
      </View>
      <Text style={s.small}>Taken in an isolated browser on our server. Your phone never opened the page. A normal-looking page is not proof of safety.</Text>
    </Animated.View>
  );
}

export type ReportProps = {
  plain: Plain;
  again?: { label: string; icon?: IconName; onPress: () => void };
  /** Say "Share this warning" even when dangerous: nothing was "sent" to the user (an IP or a domain). */
  plainShare?: boolean;
  screenshot?: { uri: string; headers?: Record<string, string> } | null;
  /** Buzz once when a fresh result arrives (not when an old report is reopened). */
  haptic?: boolean;
  /** Shown between the summary and the evidence (the AI panel). */
  children?: React.ReactNode;
};

/** The full report, drawn natively: verdict, why, what to do, what we checked. */
export function PlainReport({ plain, again, plainShare, screenshot, haptic, children }: ReportProps) {
  const tone = heroTone(plain.tone);
  useEffect(() => {
    if (!haptic) return;
    const kind = tone === 'danger' ? Haptics.NotificationFeedbackType.Error
      : tone === 'caution' ? Haptics.NotificationFeedbackType.Warning : Haptics.NotificationFeedbackType.Success;
    Haptics.notificationAsync(kind).catch(() => {});
  }, [haptic, tone]);

  const text = str(plain.share_text);
  const share = () => { Share.share({ message: text }).catch(() => {}); };
  const warn = tone === 'danger' || tone === 'caution';
  const shareLabel = !warn ? 'Share report' : tone === 'danger' && !plainShare ? 'Warn whoever sent it' : 'Share this warning';
  const reasonCount = objects(plain.reasons).length;
  const after = 2 + reasonCount;

  return (
    <View style={{ gap: 16 }}>
      <Hero plain={plain} tone={tone} />
      <Reasons plain={plain} start={1} />
      <Actions plain={plain} tone={tone} start={after} />
      {text && warn ? (
        <Animated.View entering={enter(after + 1)} style={{ gap: 10 }}>
          <Button label={shareLabel} icon="share" onPress={share} />
          {again ? <Button label={again.label} icon={again.icon ?? 'search'} kind="secondary" onPress={again.onPress} /> : null}
        </Animated.View>
      ) : again || text ? (
        <Animated.View entering={enter(after + 1)} style={{ flexDirection: 'row', gap: 10 }}>
          {again ? <Button label={again.label} icon={again.icon ?? 'search'} onPress={again.onPress} flex={1} /> : null}
          {text ? (
            <PressableScale accessibilityLabel={shareLabel} onPress={share} style={[s.shareRound, !again && { flex: 1, flexDirection: 'row', gap: 8 }]}>
              <Icon name="share" size={19} color={colors.text} />
              {!again ? <Text style={{ color: colors.text, fontSize: 15, fontFamily: fonts.bold }}>{shareLabel}</Text> : null}
            </PressableScale>
          ) : null}
        </Animated.View>
      ) : null}
      <Checks plain={plain} start={after + 2} />
      {screenshot ? <Preview source={screenshot} start={after + 3} /> : null}
      {children}
      <Text style={[s.small, { textAlign: 'center' }]}>A scan checks known warning signs at one moment in time. It can’t guarantee that something is safe.</Text>
    </View>
  );
}

const s = StyleSheet.create({
  hero: { alignItems: 'center', gap: 12, paddingVertical: 26, paddingHorizontal: 20, borderRadius: 28, borderWidth: 1, overflow: 'hidden', backgroundColor: 'rgba(14,24,37,.92)' },
  label: { flexDirection: 'row', alignItems: 'center', gap: 8, paddingVertical: 6, paddingHorizontal: 13, borderRadius: 999, borderWidth: 1 },
  headline: { color: colors.text, fontSize: 26, lineHeight: 32, fontFamily: fonts.extrabold, letterSpacing: -0.7, textAlign: 'center' },
  summary: { color: colors.soft, fontSize: 15.5, lineHeight: 24, fontFamily: fonts.regular, textAlign: 'center' },
  target: { alignSelf: 'stretch', paddingVertical: 10, paddingHorizontal: 14, borderRadius: 14, borderWidth: 1, borderColor: colors.line, backgroundColor: 'rgba(9,19,32,.85)' },
  section: { color: colors.text, fontSize: 19, fontFamily: fonts.bold, letterSpacing: -0.4 },
  card: { gap: 14, padding: 18, borderRadius: 22, borderWidth: 1, borderColor: colors.line, backgroundColor: 'rgba(14,24,37,.9)' },
  reason: { flexDirection: 'row', gap: 13, padding: 15, borderRadius: 18, borderWidth: 1, borderLeftWidth: 3, borderColor: colors.line, backgroundColor: '#0e1825' },
  dot: { width: 36, height: 36, borderRadius: 12, alignItems: 'center', justifyContent: 'center', borderWidth: 1 },
  number: { width: 26, height: 26, borderRadius: 9, alignItems: 'center', justifyContent: 'center', borderWidth: 1, marginTop: -1 },
  check: { flexDirection: 'row', alignItems: 'center', gap: 11, paddingVertical: 11, borderBottomWidth: 1, borderBottomColor: 'rgba(145,188,220,.1)' },
  shareRound: { width: 50, height: 50, borderRadius: 12, alignItems: 'center', justifyContent: 'center', backgroundColor: '#132437', borderWidth: 1, borderColor: '#2c485f' },
  small: { color: colors.faint, fontSize: 12.5, lineHeight: 19, fontFamily: fonts.regular },
});
