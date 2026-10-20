/**
 * App preferences, kept on the device. Small and synchronous to read: the
 * values load once at start-up and every screen subscribes to changes.
 */
import * as SecureStore from 'expo-secure-store';
import { useSyncExternalStore } from 'react';
import { Platform } from 'react-native';

export type Language = 'en' | 'tr' | 'ar';
export type Settings = {
  /** Vibration on results, taps and errors. */
  haptics: boolean;
  /** Open "Full technical evidence" by default (for technical users). */
  evidenceOpen: boolean;
  /** Only English ships today; the others are listed as coming soon. */
  language: Language;
};

const KEY = 'myscanner.settings';
const DEFAULTS: Settings = { haptics: true, evidenceOpen: false, language: 'en' };
let current: Settings = DEFAULTS;
const listeners = new Set<() => void>();

const store = Platform.OS === 'web'
  ? { get: async () => globalThis.localStorage?.getItem(KEY) ?? null, set: async (v: string) => globalThis.localStorage?.setItem(KEY, v) }
  : { get: () => SecureStore.getItemAsync(KEY), set: (v: string) => SecureStore.setItemAsync(KEY, v) };

export async function loadSettings() {
  try {
    const saved = JSON.parse((await store.get()) || '{}');
    current = {
      haptics: typeof saved.haptics === 'boolean' ? saved.haptics : DEFAULTS.haptics,
      evidenceOpen: typeof saved.evidenceOpen === 'boolean' ? saved.evidenceOpen : DEFAULTS.evidenceOpen,
      language: 'en',
    };
  } catch {
    current = DEFAULTS;
  }
  listeners.forEach((l) => l());
}

export function getSettings() {
  return current;
}

export function updateSettings(change: Partial<Settings>) {
  current = { ...current, ...change };
  listeners.forEach((l) => l());
  store.set(JSON.stringify(current)).catch(() => {});
}

const subscribe = (listener: () => void) => { listeners.add(listener); return () => { listeners.delete(listener); }; };

export function useSettings() {
  return useSyncExternalStore(subscribe, getSettings, getSettings);
}
