import { capitalize, t } from '@/lib/i18n';

/** MyScanner brand colours, matching the website. */
export const colors = {
  bg: '#070b14',
  bg2: '#0a111d',
  glow: '#12304a',
  surface: '#101b2b',
  surface2: '#13243a',
  input: '#091320',
  line: 'rgba(145,188,220,.18)',
  line2: '#314b63',
  text: '#edf5ff',
  soft: '#a5b6cd',
  muted: '#93a7bf',
  faint: '#7f93ad',
  cyan: '#77dcff',
  cyanSoft: '#77dcff',
  teal: '#5eead4',
  violet: '#38bdf8',
  purple: '#2dd4bf',
  green: '#4ade80',
  amber: '#fbbf24',
  red: '#fb7185',
  onAccent: '#062031',
};

/** The website's fonts: DM Sans for text, Space Mono for labels. */
export const fonts = {
  regular: 'DMSans_400Regular',
  medium: 'DMSans_500Medium',
  semibold: 'DMSans_600SemiBold',
  bold: 'DMSans_700Bold',
  extrabold: 'DMSans_800ExtraBold',
  mono: 'SpaceMono_400Regular',
  monoBold: 'SpaceMono_700Bold',
};

export const gradients = {
  accent: ['#7fe1ff', '#5eead4'] as const,
  user: ['#2563eb', '#0891b2'] as const,
  screen: ['#0d1f35', '#080d17', '#070b14'] as const,
  card: ['#121e2d', '#0e1623'] as const,
  ai: ['#38bdf8', '#2dd4bf'] as const,
  band: ['#0f2034', '#0a1424', '#0b1d2b'] as const,
};

export const radius = { sm: 10, md: 15, lg: 20, xl: 26 };
export const space = { xs: 6, sm: 10, md: 16, lg: 24, xl: 32 };

export type Tone = 'risk' | 'review' | 'safe' | 'working' | 'unknown';

// Filled from EXACT below; checked before the word matching in tone().
const EXACT_TONE: Record<string, Tone> = {};

export function tone(verdict?: string | null): Tone {
  const v = (verdict || '').toLowerCase();
  const exact = EXACT_TONE[v];
  if (exact) return exact;
  if (['malicious', 'phishing', 'dangerous', 'exposed', 'high', 'weak', 'critical'].some((w) => v.includes(w))) return 'risk';
  if (['suspicious', 'review', 'warning', 'medium', 'caution', 'fair', 'partial'].some((w) => v.includes(w))) return 'review';
  if (['harmless', 'clean', 'safe', 'low', 'not_found', 'strong', 'valid', 'completed', 'ok'].some((w) => v.includes(w))) return 'safe';
  if (['pending', 'queued', 'running', 'processing', 'started'].some((w) => v.includes(w))) return 'working';
  return 'unknown';
}

// Labels are getters so they are read in the current language.
export const toneStyle: Record<Tone, { color: string; readonly label: string }> = {
  risk: { color: colors.red, get label() { return t('High risk'); } },
  review: { color: colors.amber, get label() { return t('Needs review'); } },
  safe: { color: colors.green, get label() { return t('No threat found'); } },
  working: { color: colors.cyan, get label() { return t('Scanning…'); } },
  unknown: { color: colors.muted, get label() { return t('Unknown'); } },
};

/** Tool verdicts whose words the generic matching below would get wrong. */
const EXACT: Record<string, [Tone, () => string]> = {
  no_indicators: ['safe', () => t('No indicators found')],
  verified_connection: ['safe', () => t('Valid certificate')],
  verification_failed: ['risk', () => t('Certificate problem')],
  no_domain: ['risk', () => t('Domain does not exist')],
  not_found: ['safe', () => t('No threat found')],
  clean: ['safe', () => t('No threat found')],
  ip_high: ['risk', () => t('Reported for abuse')],
  ip_review: ['review', () => t('Some abuse reports')],
  ip_low: ['safe', () => t('No significant reports')],
};

for (const [key, [exactTone]] of Object.entries(EXACT)) EXACT_TONE[key] = exactTone;

/** Strength ratings ("weak", "very strong") in the current language. */
const STRENGTH: Record<string, () => string> = {
  weak: () => t('weak'), fair: () => t('fair'), moderate: () => t('moderate'), good: () => t('good'), strong: () => t('strong'),
};

/** Colour and label for a verdict string from the API. */
export function verdictStyle(verdict?: string | null) {
  const exact = verdict ? EXACT[verdict.trim().toLowerCase()] : undefined;
  if (exact) return { color: toneStyle[exact[0]].color, label: exact[1]() };
  const level = tone(verdict);
  // Strength ratings read better as themselves ("Weak", "Strong") than as a risk level.
  const strength = verdict?.trim().toLowerCase().match(/^(very )?(weak|fair|moderate|good|strong)$/);
  if (strength) {
    const word = STRENGTH[strength[2]]();
    return { color: toneStyle[level === 'unknown' ? 'review' : level].color, label: capitalize(strength[1] ? t('very {word}', { word }) : word) };
  }
  return level === 'unknown' && verdict ? { color: colors.muted, label: verdict.replace(/_/g, ' ') } : toneStyle[level];
}

/** "2 min ago" style time for "YYYY-MM-DD HH:MM:SS" UTC strings from the API. */
export function ago(date?: string) {
  if (!date) return '';
  const then = Date.parse(date.replace(' ', 'T') + 'Z');
  if (Number.isNaN(then)) return date;
  const s = Math.max(0, (Date.now() - then) / 1000);
  if (s < 60) return t('just now');
  if (s < 3600) return t('{n} min ago', { n: Math.floor(s / 60) });
  if (s < 86400) return t('{n} h ago', { n: Math.floor(s / 3600) });
  return t('{n} d ago', { n: Math.floor(s / 86400) });
}
