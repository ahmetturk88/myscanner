/** MyScanner brand colours, matching the website. */
export const colors = {
  bg: '#04070f',
  surface: '#0c1626',
  surface2: '#112035',
  line: '#24405c',
  text: '#e6f1fd',
  muted: '#93a7bf',
  faint: '#6b819b',
  cyan: '#22d3ee',
  blue: '#3b82f6',
  violet: '#a855f7',
  green: '#4ade80',
  amber: '#fbbf24',
  red: '#fb7185',
  onAccent: '#05202d',
};

export const radius = { sm: 10, md: 14, lg: 20 };
export const space = { xs: 6, sm: 10, md: 16, lg: 24, xl: 32 };

/** Colour and label for a verdict string from the API. */
export function verdictStyle(verdict?: string | null) {
  const v = (verdict || '').toLowerCase();
  if (['malicious', 'phishing', 'dangerous', 'exposed', 'high'].some((w) => v.includes(w))) return { color: colors.red, label: 'High risk' };
  if (['suspicious', 'review', 'warning', 'medium', 'caution'].some((w) => v.includes(w))) return { color: colors.amber, label: 'Needs review' };
  if (['harmless', 'clean', 'safe', 'low', 'not_found', 'strong'].some((w) => v.includes(w))) return { color: colors.green, label: 'No threat found' };
  if (['pending', 'queued', 'running', 'processing'].some((w) => v.includes(w))) return { color: colors.cyan, label: 'Scanning…' };
  return { color: colors.muted, label: verdict ? verdict.replace(/_/g, ' ') : 'Unknown' };
}
