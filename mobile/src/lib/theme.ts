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
  violet: '#818cf8',
  purple: '#a78bfa',
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
  user: ['#2563eb', '#7c3aed'] as const,
  screen: ['#0d1f35', '#080d17', '#070b14'] as const,
  card: ['#121e2d', '#0e1623'] as const,
  ai: ['#38bdf8', '#a78bfa'] as const,
  band: ['#0f2034', '#0a1424', '#150f2c'] as const,
};

export const radius = { sm: 10, md: 15, lg: 20, xl: 26 };
export const space = { xs: 6, sm: 10, md: 16, lg: 24, xl: 32 };

export type Tone = 'risk' | 'review' | 'safe' | 'working' | 'unknown';

export function tone(verdict?: string | null): Tone {
  const v = (verdict || '').toLowerCase();
  if (['malicious', 'phishing', 'dangerous', 'exposed', 'high', 'weak', 'critical'].some((w) => v.includes(w))) return 'risk';
  if (['suspicious', 'review', 'warning', 'medium', 'caution', 'fair', 'partial'].some((w) => v.includes(w))) return 'review';
  if (['harmless', 'clean', 'safe', 'low', 'not_found', 'strong', 'valid', 'completed', 'ok'].some((w) => v.includes(w))) return 'safe';
  if (['pending', 'queued', 'running', 'processing', 'started'].some((w) => v.includes(w))) return 'working';
  return 'unknown';
}

export const toneStyle: Record<Tone, { color: string; label: string }> = {
  risk: { color: colors.red, label: 'High risk' },
  review: { color: colors.amber, label: 'Needs review' },
  safe: { color: colors.green, label: 'No threat found' },
  working: { color: colors.cyan, label: 'Scanning…' },
  unknown: { color: colors.muted, label: 'Unknown' },
};

/** Colour and label for a verdict string from the API. */
export function verdictStyle(verdict?: string | null) {
  const t = tone(verdict);
  // Strength ratings read better as themselves ("Weak", "Strong") than as a risk level.
  if (verdict && /^(very )?(weak|fair|moderate|good|strong)$/i.test(verdict.trim())) {
    return { color: toneStyle[t === 'unknown' ? 'review' : t].color, label: verdict.trim().replace(/^./, (c) => c.toUpperCase()) };
  }
  return t === 'unknown' && verdict ? { color: colors.muted, label: verdict.replace(/_/g, ' ') } : toneStyle[t];
}

/** "2 min ago" style time for "YYYY-MM-DD HH:MM:SS" UTC strings from the API. */
export function ago(date?: string) {
  if (!date) return '';
  const then = Date.parse(date.replace(' ', 'T') + 'Z');
  if (Number.isNaN(then)) return date;
  const s = Math.max(0, (Date.now() - then) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}
