/**
 * UI translations. English source strings are the keys: t('Scan link') returns the
 * Turkish text when the app language is Turkish, otherwise the English text.
 * `{name}` placeholders are filled from `vars` in both languages.
 * Run `npm run i18n:check` after adding strings: every literal passed to t() needs an entry in TR.
 */
import { TR } from '@/lib/i18n-tr';
import { getSettings, useSettings } from '@/lib/settings';

export type Lang = 'en' | 'tr';

const asLang = (value: string): Lang => (value === 'tr' ? 'tr' : 'en');

/** The language the UI is shown in right now. */
export function lang(): Lang {
  return asLang(getSettings().language);
}

/** Same as lang(), as a hook that re-renders when the language changes. */
export function useLang(): Lang {
  return asLang(useSettings().language);
}

export function t(english: string, vars?: Record<string, string | number>): string {
  const text = lang() === 'tr' ? TR[english] ?? english : english;
  if (!vars) return text;
  return text.replace(/\{(\w+)\}/g, (match, name: string) => (name in vars ? String(vars[name]) : match));
}

/** Locale for numbers and letter case. */
export function locale() {
  return lang() === 'tr' ? 'tr-TR' : 'en-US';
}

/** Upper case that respects Turkish letters (i → İ). Use it for kickers and mono labels. */
export function upper(text: string) {
  return text.toLocaleUpperCase(locale());
}

/** First letter in upper case, the rest unchanged. */
export function capitalize(text: string) {
  return text.charAt(0).toLocaleUpperCase(locale()) + text.slice(1);
}
