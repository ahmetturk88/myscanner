/** MyScanner brand colours, matching the website. */
export const colors = {
  bg: '#04070f',
  bg2: '#07101d',
  glow: '#123156',
  surface: '#0c1626',
  surface2: '#0f1f33',
  input: '#050c18',
  line: '#1f3650',
  line2: '#2e4f70',
  text: '#e6f1fd',
  soft: '#c4d6ea',
  muted: '#93a7bf',
  faint: '#6b819b',
  cyan: '#22d3ee',
  cyanSoft: '#67e8f9',
  violet: '#818cf8',
  purple: '#a78bfa',
  green: '#4ade80',
  amber: '#fbbf24',
  red: '#fb7185',
  onAccent: '#04121f',
};

export const gradients = {
  accent: ['#22d3ee', '#818cf8'] as const,
  user: ['#2563eb', '#7c3aed'] as const,
  screen: ['#0f2a4a', '#07101d', '#04070f'] as const,
  card: ['#0f2440', '#0a1424'] as const,
  ai: ['#22d3ee', '#a78bfa'] as const,
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
