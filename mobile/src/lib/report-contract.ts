/** The plain-language summary every tool returns as `plain` (built on the server). */
export type Plain = {
  tone: string; label: string; headline: string; summary: string;
  url?: { prefix?: string; host?: string; rest?: string };
  reasons?: { tone: string; title: string; detail: string }[];
  actions?: string[];
  checks?: { name: string; state: string; result: string }[];
  tally?: string; share_text?: string; why_title?: string; checked?: string;
  /** Why a link report has no page preview; shown in place of the screenshot. */
  no_preview?: string;
};

export type HeroTone = 'danger' | 'caution' | 'unknown' | 'safe' | 'info';
export type State = 'bad' | 'warn' | 'ok' | 'na' | 'info';

/** Unknown/prototype keys never select styles. Server decisions are not rescored. */
export const heroTone = (value: unknown): HeroTone =>
  typeof value === 'string' && ['danger', 'caution', 'unknown', 'safe', 'info'].includes(value) ? value as HeroTone : 'unknown';
export const state = (value: unknown): State =>
  typeof value === 'string' && ['bad', 'warn', 'ok', 'na', 'info'].includes(value) ? value as State : 'na';

/** True when a tool result carries a summary this screen can draw. */
export function hasPlain(value: any): value is Plain {
  return !!value && typeof value === 'object' && !Array.isArray(value) && typeof value.headline === 'string';
}

/**
 * Background jobs (site, subdomains) answer {message, status, result: {…, plain}}: the report
 * is one level down. Returns the object that carries the summary, or the input unchanged.
 */
export function reportOf(data: any) {
  return data && !hasPlain(data.plain) && data.result && typeof data.result === 'object' && hasPlain(data.result.plain) ? data.result : data;
}

/** The evidence below the summary: everything except the summary itself. */
export function withoutPlain(result: Record<string, unknown>) {
  const { plain: _plain, ...rest } = result;
  return rest;
}

