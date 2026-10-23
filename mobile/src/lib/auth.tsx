import * as SecureStore from 'expo-secure-store';
import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { Platform } from 'react-native';

import { api, loadToken, saveToken, setSignedOutHandler, type User } from '@/lib/api';
import { providerSignIn } from '@/lib/oauth';

type AuthState = {
  ready: boolean;
  user: User | null;
  signIn: (email: string, password: string) => Promise<void>;
  signInWith: (provider: string) => Promise<void>;
  signOut: () => Promise<void>;
  refresh: () => Promise<void>;
  forget: () => Promise<void>;
};

const AuthContext = createContext<AuthState | null>(null);

// The last profile, so a signed-in person sees the app at once (and offline) instead of waiting for /me.
const USER_KEY = 'myscanner.user';
const profileStore = Platform.OS === 'web'
  ? { get: async () => globalThis.localStorage?.getItem(USER_KEY) ?? null, set: async (v: string) => globalThis.localStorage?.setItem(USER_KEY, v),
      remove: async () => globalThis.localStorage?.removeItem(USER_KEY) }
  : { get: () => SecureStore.getItemAsync(USER_KEY), set: (v: string) => SecureStore.setItemAsync(USER_KEY, v),
      remove: () => SecureStore.deleteItemAsync(USER_KEY) };

async function remember(user: User | null) {
  try {
    if (user) await profileStore.set(JSON.stringify({ ...user, allowance: [] }));
    else await profileStore.remove();
  } catch { /* only a start-up shortcut */ }
}

async function remembered(): Promise<User | null> {
  try {
    const saved = JSON.parse((await profileStore.get()) || 'null');
    return saved && typeof saved.id === 'number' ? saved : null;
  } catch {
    return null;
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(false);
  const [user, setUser] = useState<User | null>(null);

  const refresh = useCallback(async () => {
    const { user: fresh } = await api.me();
    setUser(fresh);
    remember(fresh);
  }, []);

  useEffect(() => {
    setSignedOutHandler(() => { setUser(null); remember(null); });
    (async () => {
      try {
        if (!(await loadToken())) return;
        const cached = await remembered();
        if (cached) {
          // Open straight away with the saved profile; /me updates it, and a rejected token signs out.
          setUser(cached);
          setReady(true);
          refresh().catch(() => {});
          return;
        }
        await refresh();
      } catch {
        // Offline or token rejected: the sign-in screen handles both.
      } finally {
        setReady(true);
      }
    })();
  }, [refresh]);

  const value = useMemo<AuthState>(() => ({
    ready,
    user,
    refresh,
    signIn: async (email, password) => {
      const result = await api.login(email.trim(), password, `${Platform.OS} app`);
      await saveToken(result.token);
      setUser(result.user);
      remember(result.user);
    },
    signInWith: async (provider) => {
      const { code, verifier } = await providerSignIn(provider);
      const result = await api.exchange(code, verifier, `${Platform.OS} app`);
      await saveToken(result.token);
      setUser(result.user);
      remember(result.user);
    },
    signOut: async () => {
      try { await api.logout(); } catch { /* the token is dropped locally either way */ }
      await saveToken(null);
      setUser(null);
      remember(null);
    },
    forget: async () => {
      await saveToken(null);
      setUser(null);
      remember(null);
    },
  }), [ready, user, refresh]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error('useAuth must be used inside AuthProvider');
  return value;
}
