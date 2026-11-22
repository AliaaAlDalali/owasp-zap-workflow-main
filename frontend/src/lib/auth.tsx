import { createContext, type ReactNode, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { post, request, setUnauthorizedHandler } from './api';
import type { User } from './types';

export interface RegisterInput {
  email: string;
  name: string;
  password: string;
  organization_name: string;
}

interface AuthValue {
  /** undefined while the session is being checked, null when signed out. */
  user: User | null | undefined;
  signIn: (email: string, password: string) => Promise<void>;
  register: (input: RegisterInput) => Promise<void>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthValue | null>(null);

/** Owns the signed-in user. The session itself is an HttpOnly cookie the page never sees. */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null | undefined>(undefined);

  useEffect(() => {
    // Any 401 means the session ended: RequireAuth then sends the visitor to sign-in.
    setUnauthorizedHandler(() => setUser(null));
    const controller = new AbortController();
    request<User>('/auth/me', { signal: controller.signal, skipAuthRedirect: true })
      .then(setUser)
      .catch(() => {
        if (!controller.signal.aborted) setUser(null);
      });
    return () => controller.abort();
  }, []);

  const signIn = useCallback(async (email: string, password: string) => {
    setUser(await post<User>('/auth/login', { email, password }));
  }, []);

  const register = useCallback(async (input: RegisterInput) => {
    setUser(await post<User>('/auth/register', input));
  }, []);

  const signOut = useCallback(async () => {
    try {
      await post<null>('/auth/logout');
    } finally {
      setUser(null);
    }
  }, []);

  const value = useMemo(() => ({ user, signIn, register, signOut }), [user, signIn, register, signOut]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error('useAuth must be used inside AuthProvider');
  return value;
}
