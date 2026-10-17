/**
 * The website's page frame, rebuilt natively: top bar with the toolkit menu,
 * the tool switcher, the footer and the floating AI button.
 */
import * as Haptics from 'expo-haptics';
import { LinearGradient } from 'expo-linear-gradient';
import { router } from 'expo-router';
import * as WebBrowser from 'expo-web-browser';
import { useMemo, useState, type ReactNode } from 'react';
import { Modal, Pressable, ScrollView, StyleSheet, Text, TextInput, View } from 'react-native';
import { SafeAreaView, useSafeAreaInsets } from 'react-native-safe-area-context';

import { BrandMark } from '@/components/brand';
import { Icon, type IconName } from '@/components/icon';
import { Backdrop, Eyebrow } from '@/components/ui';
import { SITE } from '@/lib/api';
import { useAuth } from '@/lib/auth';
import { colors, fonts, gradients } from '@/lib/theme';
import { CATEGORIES, TOOLS, type Tool } from '@/lib/tools';

export function openTool(tool: Tool, replace = false) {
  const go = replace ? router.replace : router.push;
  if (tool.route === 'url') router.navigate('/');
  else if (tool.route) go(tool.route);
  else go({ pathname: '/tool/[name]', params: { name: tool.name } });
}

const openSite = (path: string) => WebBrowser.openBrowserAsync(`${SITE}${path}`);

/** The website's top bar: brand, new scan, account and the toolkit menu. */
function TopBar({ onMenu }: { onMenu: () => void }) {
  const { user } = useAuth();
  return (
    <View style={s.top}>
      <Pressable accessibilityRole="link" accessibilityLabel="MyScanner home" onPress={() => router.navigate('/')} style={s.brand}>
        <BrandMark size={34} />
        <Text style={s.brandText}>My<Text style={{ color: '#00c8f2' }}>Scanner</Text></Text>
      </Pressable>
      <View style={{ flexDirection: 'row', alignItems: 'center', gap: 8, marginLeft: 'auto' }}>
        <Pressable accessibilityRole="button" accessibilityLabel="New scan" onPress={() => router.navigate('/')}>
          <LinearGradient colors={gradients.accent} start={{ x: 0, y: 0 }} end={{ x: 1, y: 0 }} style={s.scanButton}>
            <Icon name="bolt" size={18} color={colors.onAccent} />
          </LinearGradient>
        </Pressable>
        <Pressable accessibilityRole="button" accessibilityLabel="Account" onPress={() => router.navigate('/account')} style={s.avatarRing}>
          <LinearGradient colors={['#1f6f99', '#5b3fb0']} style={s.avatar}>
            <Text style={{ color: '#fff', fontFamily: fonts.bold, fontSize: 14 }}>{(user?.username || '?')[0].toUpperCase()}</Text>
          </LinearGradient>
        </Pressable>
        <Pressable accessibilityRole="button" accessibilityLabel="Open navigation and tools" onPress={onMenu} style={s.menuButton}>
          <Text style={{ color: '#bceaff', fontSize: 20, lineHeight: 22 }}>☰</Text>
        </Pressable>
      </View>
    </View>
  );
}

/** "THE TOOLKIT" dialog, the same as the website's menu. */
function Toolkit({ visible, onClose }: { visible: boolean; onClose: () => void }) {
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState<string>('all');
  const shown = useMemo(() => TOOLS.filter((t) => (category === 'all' || t.category === category)
    && `${t.title} ${t.menu}`.toLowerCase().includes(query.trim().toLowerCase())), [query, category]);
  const go = (fn: () => void) => { onClose(); setTimeout(fn, 150); };
  const links: [string, () => void][] = [
    ['Home', () => router.navigate('/')], ['History', () => router.navigate('/history')], ['Assistant', () => router.navigate('/assistant')],
    ['Profile', () => router.navigate('/account')], ['About', () => openSite('/about')], ['Contact', () => openSite('/contact')],
  ];
  return (
    <Modal visible={visible} animationType="fade" transparent onRequestClose={onClose} statusBarTranslucent>
      <View style={s.backdrop}>
        <SafeAreaView style={{ flex: 1, padding: 12 }}>
          <LinearGradient colors={['#0d192a', '#080f1c']} start={{ x: 0, y: 0 }} end={{ x: 1, y: 1 }} style={s.dialog}>
            <ScrollView contentContainerStyle={{ padding: 22, gap: 18 }} keyboardShouldPersistTaps="handled">
              <View style={{ flexDirection: 'row', alignItems: 'flex-start', gap: 12 }}>
                <View style={{ flex: 1, gap: 8 }}>
                  <Eyebrow color="#59ddeb">The toolkit</Eyebrow>
                  <Text style={s.dialogTitle}>Find your next inspection.</Text>
                  <Text style={s.dialogLead}>Choose the evidence you want to understand.</Text>
                </View>
                <Pressable accessibilityRole="button" accessibilityLabel="Close navigation" onPress={onClose} style={s.close}>
                  <Icon name="close" size={18} color={colors.text} />
                </Pressable>
              </View>
              <View style={s.quicknav}>
                {links.map(([label, fn]) => (
                  <Pressable key={label} onPress={() => go(fn)} hitSlop={6}><Text style={s.quicklink}>{label}</Text></Pressable>
                ))}
              </View>
              <View style={{ gap: 8 }}>
                <Text style={{ color: '#a2bad3', fontSize: 13, fontFamily: fonts.regular }}>Search tools</Text>
                <TextInput value={query} onChangeText={setQuery} placeholder="Try certificate, email, DNS…" placeholderTextColor="#5f7590"
                  style={s.search} autoCorrect={false} />
              </View>
              <View style={{ flexDirection: 'row', flexWrap: 'wrap', gap: 8 }}>
                {CATEGORIES.map((c) => {
                  const on = category === c.key;
                  return (
                    <Pressable key={c.key} onPress={() => setCategory(c.key)} accessibilityState={{ selected: on }}
                      style={[s.filter, on && { borderColor: '#2b7289', backgroundColor: '#103546' }]}>
                      <Text style={{ color: on ? '#9eeaff' : '#9eb3cb', fontSize: 13, fontFamily: fonts.medium }}>{c.label}</Text>
                    </Pressable>
                  );
                })}
              </View>
              <View style={{ gap: 10 }}>
                {shown.map((tool) => (
                  <Pressable key={tool.name} onPress={() => go(() => openTool(tool))}
                    style={({ pressed }) => [s.toolRow, pressed && { borderColor: '#358ca8', backgroundColor: '#142b40' }]}>
                    <View style={s.toolIcon}><Icon name={tool.icon} size={21} color="#77dcff" /></View>
                    <View style={{ flex: 1, gap: 3 }}>
                      <Text style={{ color: '#e2edfa', fontSize: 15, fontFamily: fonts.bold }}>{tool.title}</Text>
                      <Text style={{ color: '#94acc6', fontSize: 13, lineHeight: 19, fontFamily: fonts.regular }}>{tool.menu}</Text>
                    </View>
                    <Text style={{ color: '#57cedc', fontSize: 17 }}>↗</Text>
                  </Pressable>
                ))}
                {!shown.length ? <Text style={{ color: colors.muted, fontFamily: fonts.regular }}>No tools match your search.</Text> : null}
              </View>
              <Text style={{ color: colors.muted, fontSize: 13, lineHeight: 21, fontFamily: fonts.regular }}>
                Results reflect available evidence, not a guarantee of safety.
              </Text>
            </ScrollView>
          </LinearGradient>
        </SafeAreaView>
      </View>
    </Modal>
  );
}

/** Breadcrumbs and the horizontal tool switcher shown above every tool. */
export function ToolRail({ active }: { active: string }) {
  const current = TOOLS.find((t) => t.name === active);
  return (
    <View style={{ gap: 12 }}>
      <View style={{ flexDirection: 'row', alignItems: 'center', gap: 8 }}>
        <Pressable onPress={() => router.navigate('/')}><Text style={s.crumb}>Workspace</Text></Pressable>
        <Text style={s.crumb}>/</Text>
        <Text style={s.crumb}>Tools</Text>
        <Text style={s.crumb}>/</Text>
        {current ? <Icon name={current.icon} size={16} color={colors.text} /> : null}
        <Text style={[s.crumb, { color: colors.text, fontFamily: fonts.bold }]}>{current?.title}</Text>
      </View>
      <ScrollView horizontal showsHorizontalScrollIndicator={false} contentContainerStyle={{ gap: 8, paddingRight: 20 }}>
        {TOOLS.map((tool) => {
          const on = tool.name === active;
          const pill = (
            <View style={s.switchInner}>
              <Icon name={tool.icon} size={15} color={on ? '#effaff' : '#a9bbd2'} />
              <Text style={{ color: on ? '#effaff' : '#a9bbd2', fontSize: 14, fontFamily: fonts.semibold }}>{tool.short}</Text>
            </View>
          );
          return (
            <Pressable key={tool.name} accessibilityRole="tab" accessibilityState={{ selected: on }}
              onPress={() => { if (!on) { Haptics.selectionAsync().catch(() => {}); openTool(tool, true); } }}>
              {on ? (
                <LinearGradient colors={['rgba(127,225,255,.2)', 'rgba(94,234,212,.14)']} start={{ x: 0, y: 0 }} end={{ x: 1, y: 0 }}
                  style={[s.switch, { borderColor: 'rgba(119,220,255,.55)' }]}>{pill}</LinearGradient>
              ) : <View style={s.switch}>{pill}</View>}
            </Pressable>
          );
        })}
      </ScrollView>
    </View>
  );
}

/** Numbered explainer cards ("01 / Connection …") under each tool. */
export function Steps({ steps }: { steps: [string, string][] }) {
  if (!steps.length) return null;
  return (
    <View style={{ gap: 12 }}>
      {steps.map(([title, text], i) => (
        <View key={title} style={s.step}>
          <Text style={{ color: '#59c8e6', fontSize: 18, fontFamily: fonts.mono }}>{`0${i + 1}`}</Text>
          <Text style={{ color: colors.text, fontSize: 15, fontFamily: fonts.bold }}>{title}</Text>
          <Text style={{ color: colors.soft, fontSize: 14, lineHeight: 22, fontFamily: fonts.regular }}>{text}</Text>
        </View>
      ))}
    </View>
  );
}

function FooterLink({ icon, label, onPress }: { icon: IconName; label: string; onPress: () => void }) {
  return (
    <Pressable onPress={onPress} style={{ flexDirection: 'row', alignItems: 'center', gap: 9, paddingVertical: 6 }}>
      <Icon name={icon} size={15} color="#90a8c2" />
      <Text style={{ color: '#90a8c2', fontSize: 14, fontFamily: fonts.regular }}>{label}</Text>
    </Pressable>
  );
}

/** The website footer: call-to-action band, brand, links and principles. */
export function Footer() {
  const tool = (name: string) => () => openTool(TOOLS.find((t) => t.name === name)!);
  return (
    <View style={{ gap: 30, marginTop: 30 }}>
      <LinearGradient colors={gradients.band} start={{ x: 0, y: 0 }} end={{ x: 1, y: 1 }} style={s.band}>
        <Eyebrow color="#59ddeb">Evidence before trust</Eyebrow>
        <Text style={s.bandTitle}>A clearer view.{'\n'}<Text style={{ color: colors.teal }}>A better next step.</Text></Text>
        <Text style={{ color: '#a9bbd2', fontSize: 15.5, lineHeight: 26, fontFamily: fonts.regular }}>
          Review the destination, identity and infrastructure behind the signal. Understand what was observed and what remains unknown.
        </Text>
        <Pressable onPress={() => router.navigate('/history')}>
          <LinearGradient colors={gradients.accent} start={{ x: 0, y: 0 }} end={{ x: 1, y: 0 }} style={s.bandButton}>
            <Text style={{ color: colors.onAccent, fontFamily: fonts.bold, fontSize: 14.5 }}>Open your workspace</Text>
            <Text style={{ color: colors.onAccent, fontFamily: fonts.bold }}>→</Text>
          </LinearGradient>
        </Pressable>
        <Pressable onPress={() => router.navigate('/')} style={s.ghost}><Text style={{ color: '#d7e8f8', fontFamily: fonts.semibold, fontSize: 15 }}>Scan a link</Text></Pressable>
      </LinearGradient>
      <View style={{ gap: 14 }}>
        <View style={{ flexDirection: 'row', alignItems: 'center', gap: 10 }}>
          <BrandMark size={52} />
          <View>
            <Text style={{ color: colors.text, fontSize: 30, fontFamily: fonts.extrabold, letterSpacing: -1 }}>My<Text style={{ color: '#4fc9f2' }}>Scanner</Text></Text>
            <Text style={{ color: '#7f95b3', fontSize: 9, letterSpacing: 3, fontFamily: fonts.medium }}>SCAN · VERIFY · STAY PROTECTED</Text>
          </View>
        </View>
        <Text style={{ color: '#8fa7c0', fontSize: 14, lineHeight: 23, fontFamily: fonts.regular }}>Tools for reviewing security evidence across links, identity, files and infrastructure.</Text>
        <View style={s.status}><View style={s.statusDot} /><Text style={{ color: '#9ff3d5', fontFamily: fonts.monoBold, fontSize: 12 }}>Pre-launch · testing in progress</Text></View>
      </View>
      <View style={{ flexDirection: 'row', gap: 18 }}>
        <View style={{ flex: 1 }}>
          <Text style={s.footHead}>INSPECT</Text>
          <FooterLink icon="link" label="Links & destinations" onPress={() => router.navigate('/')} />
          <FooterLink icon="mail" label="Email identity" onPress={tool('email')} />
          <FooterLink icon="file" label="Files & hashes" onPress={tool('file')} />
          <FooterLink icon="globe" label="Website evidence" onPress={tool('site')} />
          <FooterLink icon="key" label="Password security" onPress={tool('password')} />
        </View>
        <View style={{ flex: 1 }}>
          <Text style={s.footHead}>UNDERSTAND</Text>
          <FooterLink icon="server" label="IP intelligence" onPress={tool('ip')} />
          <FooterLink icon="search" label="Domain & DNS" onPress={tool('domain')} />
          <FooterLink icon="layers" label="Subdomains" onPress={tool('subdomain')} />
          <FooterLink icon="lock" label="TLS certificates" onPress={tool('ssl')} />
          <FooterLink icon="qr" label="QR payloads" onPress={tool('qr')} />
        </View>
      </View>
      <View>
        <Text style={s.footHead}>CONNECT</Text>
        <FooterLink icon="shield" label="About MyScanner" onPress={() => openSite('/about')} />
        <FooterLink icon="mail" label="Contact & feedback" onPress={() => openSite('/contact')} />
        <FooterLink icon="shield" label="Report a vulnerability" onPress={() => openSite('/contact?topic=Security+Report')} />
      </View>
      <View style={s.principles}>
        {['Evidence with context', 'Coverage made visible', 'Public-target boundaries'].map((p, i) => (
          <Text key={p} style={{ color: '#87a2bd', fontSize: 12.5, fontFamily: fonts.regular }}>
            <Text style={{ color: '#51cfe7', fontFamily: fonts.mono }}>{`0${i + 1}  `}</Text>{p}
          </Text>
        ))}
      </View>
      <View style={{ gap: 6 }}>
        <Text style={{ color: '#849bb5', fontSize: 12, fontFamily: fonts.regular }}>© {new Date().getFullYear()} MyScanner  /  Built by Ahmed Sairafi in Istanbul</Text>
        <View style={{ flexDirection: 'row', gap: 16 }}>
          <Pressable onPress={() => openSite('/privacy')}><Text style={s.legal}>Privacy Policy</Text></Pressable>
          <Pressable onPress={() => openSite('/terms')}><Text style={s.legal}>Terms of Service</Text></Pressable>
        </View>
      </View>
    </View>
  );
}

/** The floating "Ask AI" orb in the corner, as on the website. */
function AIFab() {
  const insets = useSafeAreaInsets();
  return (
    <Pressable accessibilityRole="button" accessibilityLabel="Ask the AI assistant" onPress={() => router.navigate('/assistant')}
      style={[s.fabWrap, { bottom: insets.bottom + 18 }]}>
      <LinearGradient colors={['#22d3ee', '#818cf8']} start={{ x: 0, y: 0 }} end={{ x: 1, y: 1 }} style={s.fab}>
        <View style={s.fabCore}><Text style={{ color: '#67e8f9', fontSize: 16 }}>✦</Text></View>
      </LinearGradient>
    </Pressable>
  );
}

/** A full website-style page: top bar, scrolling content, footer and AI button. */
export function Page({ children, footer = true, fab = true, scroll = true }: { children: ReactNode; footer?: boolean; fab?: boolean; scroll?: boolean }) {
  const [menu, setMenu] = useState(false);
  return (
    <Backdrop>
      <SafeAreaView style={{ flex: 1 }} edges={['top']}>
        <TopBar onMenu={() => setMenu(true)} />
        {scroll ? (
          <ScrollView contentContainerStyle={{ padding: 16, paddingTop: 18, paddingBottom: 40, gap: 20 }} keyboardShouldPersistTaps="handled" showsVerticalScrollIndicator={false}>
            {children}
            {footer ? <Footer /> : null}
          </ScrollView>
        ) : <View style={{ flex: 1 }}>{children}</View>}
        {fab ? <AIFab /> : null}
        <Toolkit visible={menu} onClose={() => setMenu(false)} />
      </SafeAreaView>
    </Backdrop>
  );
}

const s = StyleSheet.create({
  top: { flexDirection: 'row', alignItems: 'center', paddingHorizontal: 14, height: 62, backgroundColor: 'rgba(8,13,23,.92)', borderBottomWidth: 1, borderBottomColor: '#263950' },
  brand: { flexDirection: 'row', alignItems: 'center', gap: 9 },
  brandText: { color: colors.text, fontSize: 19, fontFamily: fonts.extrabold, letterSpacing: -0.6 },
  scanButton: { width: 38, height: 38, borderRadius: 11, alignItems: 'center', justifyContent: 'center' },
  avatarRing: { padding: 3, borderRadius: 999, borderWidth: 1, borderColor: '#2a4258', backgroundColor: '#0f1d2e' },
  avatar: { width: 30, height: 30, borderRadius: 15, alignItems: 'center', justifyContent: 'center' },
  menuButton: { width: 38, height: 38, borderRadius: 10, alignItems: 'center', justifyContent: 'center', borderWidth: 1, borderColor: '#324d69', backgroundColor: '#112338' },
  backdrop: { flex: 1, backgroundColor: 'rgba(2,7,17,.78)' },
  dialog: { flex: 1, borderRadius: 24, borderWidth: 1, borderColor: '#34516a', overflow: 'hidden' },
  dialogTitle: { color: colors.text, fontSize: 27, fontFamily: fonts.bold, letterSpacing: -1, lineHeight: 31 },
  dialogLead: { color: colors.muted, fontSize: 14.5, lineHeight: 23, fontFamily: fonts.regular },
  close: { width: 36, height: 36, borderRadius: 18, alignItems: 'center', justifyContent: 'center', borderWidth: 1, borderColor: '#34516a', backgroundColor: '#18283b' },
  quicknav: { flexDirection: 'row', flexWrap: 'wrap', gap: 18, rowGap: 12, paddingBottom: 16, borderBottomWidth: 1, borderBottomColor: '#263950' },
  quicklink: { color: '#adc3da', fontSize: 15, fontFamily: fonts.regular },
  search: { minHeight: 52, borderRadius: 12, borderWidth: 1, borderColor: '#31506b', backgroundColor: '#060e1a', color: colors.text, paddingHorizontal: 16, fontSize: 15, fontFamily: fonts.regular },
  filter: { paddingVertical: 8, paddingHorizontal: 13, borderRadius: 20, borderWidth: 1, borderColor: '#2d435c', backgroundColor: '#132135' },
  toolRow: { flexDirection: 'row', alignItems: 'center', gap: 13, padding: 15, borderRadius: 14, borderWidth: 1, borderColor: '#263e55', backgroundColor: '#101e30' },
  toolIcon: { width: 43, height: 43, borderRadius: 11, alignItems: 'center', justifyContent: 'center', backgroundColor: '#1d435b', borderWidth: 1, borderColor: '#31556e' },
  crumb: { color: '#7f93ad', fontSize: 14, fontFamily: fonts.regular },
  switch: { borderRadius: 999, borderWidth: 1, borderColor: 'rgba(145,188,220,.16)', backgroundColor: 'rgba(13,24,40,.7)' },
  switchInner: { flexDirection: 'row', alignItems: 'center', gap: 8, paddingVertical: 9, paddingHorizontal: 14 },
  step: { gap: 8, padding: 18, borderRadius: 16, borderWidth: 1, borderColor: colors.line, backgroundColor: '#0e1726' },
  band: { borderRadius: 26, borderWidth: 1, borderColor: 'rgba(119,220,255,.22)', padding: 24, gap: 16 },
  bandTitle: { color: '#eef6ff', fontSize: 34, lineHeight: 37, fontFamily: fonts.bold, letterSpacing: -1.4 },
  bandButton: { flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between', alignSelf: 'flex-start', gap: 26, borderRadius: 11, paddingVertical: 12, paddingHorizontal: 16 },
  ghost: { alignSelf: 'flex-start', paddingVertical: 12, paddingHorizontal: 16, borderRadius: 11, borderWidth: 1, borderColor: '#33506a' },
  status: { flexDirection: 'row', alignItems: 'center', gap: 8, alignSelf: 'flex-start', paddingVertical: 7, paddingHorizontal: 12, borderRadius: 999, borderWidth: 1, borderColor: 'rgba(74,222,128,.35)', backgroundColor: 'rgba(16,40,32,.5)' },
  statusDot: { width: 8, height: 8, borderRadius: 4, backgroundColor: '#4ade80' },
  footHead: { color: '#cbdcf0', letterSpacing: 1.5, fontSize: 12, fontFamily: fonts.monoBold, marginBottom: 10 },
  principles: { gap: 8, paddingVertical: 16, borderTopWidth: 1, borderBottomWidth: 1, borderColor: '#24364c' },
  legal: { color: '#a9bfd6', fontSize: 12.5, fontFamily: fonts.regular },
  fabWrap: { position: 'absolute', right: 16 },
  fab: { width: 58, height: 58, borderRadius: 29, alignItems: 'center', justifyContent: 'center', shadowColor: '#22d3ee', shadowOpacity: 0.5, shadowRadius: 14, shadowOffset: { width: 0, height: 8 } },
  fabCore: { width: 40, height: 40, borderRadius: 20, backgroundColor: '#06121f', alignItems: 'center', justifyContent: 'center' },
});
