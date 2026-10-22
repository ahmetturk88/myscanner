/**
 * In-app update prompts. The server says whether this build is still
 * supported (GET /app/version, services/app_release.py): below the minimum the
 * app shows only the update screen; below the latest it offers the update
 * once, and "Later" hides it until a newer build comes out. A failed check
 * never blocks the app.
 */
import Constants from 'expo-constants';
import { useCallback, useEffect, useRef, useState } from 'react';
import { AppState, Linking } from 'react-native';

import { SITE } from '@/lib/api';
import { getSettings, updateSettings, useSettings } from '@/lib/settings';

export type UpdateKind = 'required' | 'available' | 'none';
type Policy = { update: UpdateKind; latest_build: number; store_url: string };

export const BUILD = Number(Constants.expoConfig?.android?.versionCode) || 0;
export const VERSION = Constants.expoConfig?.version ?? '';
const PACKAGE = Constants.expoConfig?.android?.package || 'com.myscanners.app';
const STORE_URL = `https://play.google.com/store/apps/details?id=${PACKAGE}`;
const WAIT = 2500;            // longest the splash screen waits for the first check
const RECHECK = 30 * 60_000;  // when the app comes back to the front

async function fetchPolicy(): Promise<Policy | null> {
  if (!BUILD) return null;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8000);
  try {
    const response = await fetch(`${SITE}/api/mobile/v1/app/version?build=${BUILD}`, { signal: controller.signal, headers: { Accept: 'application/json' } });
    return response.ok ? await response.json() : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/** Opens MyScanner in the Play Store app, or on the Play website when the store app is missing. */
export async function openStore(url = STORE_URL) {
  try {
    await Linking.openURL(`market://details?id=${PACKAGE}`);
  } catch {
    await Linking.openURL(url).catch(() => {});
  }
}

export function useAppUpdate() {
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [checked, setChecked] = useState(false);
  const last = useRef(0);
  const { skippedBuild } = useSettings();

  useEffect(() => {
    let alive = true;
    const run = async () => {
      last.current = Date.now();
      const result = await fetchPolicy();
      if (!alive) return;
      if (result) setPolicy(result);
      setChecked(true);
    };
    run();
    const giveUp = setTimeout(() => setChecked(true), WAIT);
    const sub = AppState.addEventListener('change', (state) => {
      if (state === 'active' && Date.now() - last.current > RECHECK) run();
    });
    return () => { alive = false; clearTimeout(giveUp); sub.remove(); };
  }, []);

  let kind: UpdateKind = policy?.update ?? 'none';
  if (kind === 'available' && policy && skippedBuild >= policy.latest_build) kind = 'none';
  const later = useCallback(() => {
    if (policy) updateSettings({ skippedBuild: Math.max(getSettings().skippedBuild, policy.latest_build) });
  }, [policy]);
  const update = useCallback(() => openStore(policy?.store_url), [policy]);
  return { checked, kind, later, update };
}
