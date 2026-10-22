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
  /** English and Turkish ship today; Arabic is listed as coming soon. */
  language: Language;
  /** The newest app build the user chose to update later; its prompt is not shown again. */
  skippedBuild: number;
};

const KEY = 'myscanner.settings';
const DEFAULTS: Settings = { haptics: true, evidenceOpen: false, language: 'en', skippedBuild: 0 };
let current: Settings = DEFAULTS;
/** False until the saved settings have been read (the first screen waits for it). */
let ready = false;
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
      language: saved.language === 'tr' ? 'tr' : 'en',
      skippedBuild: Number.isInteger(saved.skippedBuild) ? saved.skippedBuild : 0,
    };
  } catch {
    current = DEFAULTS;
  }
  ready = true;
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

const isReady = () => ready;

/** True once loadSettings() has finished. */
export function useSettingsReady() {
  return useSyncExternalStore(subscribe, isReady, isReady);
}
