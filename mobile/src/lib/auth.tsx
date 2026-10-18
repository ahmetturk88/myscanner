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

export function AuthProvider({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(false);
  const [user, setUser] = useState<User | null>(null);

  const refresh = useCallback(async () => {
    const { user: fresh } = await api.me();
    setUser(fresh);
  }, []);

  useEffect(() => {
    setSignedOutHandler(() => setUser(null));
    (async () => {
      try {
        if (await loadToken()) await refresh();
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
    },
    signInWith: async (provider) => {
      const { code, verifier } = await providerSignIn(provider);
      const result = await api.exchange(code, verifier, `${Platform.OS} app`);
      await saveToken(result.token);
      setUser(result.user);
    },
    signOut: async () => {
      try { await api.logout(); } catch { /* the token is dropped locally either way */ }
      await saveToken(null);
      setUser(null);
    },
    forget: async () => {
      await saveToken(null);
      setUser(null);
    },
  }), [ready, user, refresh]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error('useAuth must be used inside AuthProvider');
  return value;
}
