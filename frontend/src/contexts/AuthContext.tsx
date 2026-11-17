import { createContext, useContext, useState, useCallback, useEffect, type ReactNode } from 'react';
import { authAPI, isAuthenticationFailure, restoreSession } from '../api/client';
import type { User, AuthResponse } from '../types';

interface AuthState {
  user: User | null;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<AuthResponse>;
  register: (name: string, email: string, password: string) => Promise<AuthResponse>;
  logout: () => Promise<void>;
  loadUser: () => Promise<void>;
}

const AuthContext = createContext<AuthState | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const login = useCallback(async (email: string, password: string) => {
    const response = await authAPI.login(email, password);
    setUser(response.user);
    return response;
  }, []);

  const register = useCallback(async (name: string, email: string, password: string) => {
    const response = await authAPI.register(name, email, password);
    setUser(response.user);
    return response;
  }, []);

  const logout = useCallback(async () => {
    try {
      await authAPI.logout();
    } finally {
      setUser(null);
    }
  }, []);

  const loadUser = useCallback(async () => {
    try {
      const restored = await restoreSession();
      if (!restored) {
        setUser(null);
        return;
      }

      const profile = await authAPI.getProfile();
      setUser(profile);
    } catch (error) {
      if (isAuthenticationFailure(error)) {
        setUser(null);
      }
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadUser();
  }, [loadUser]);

  return (
    <AuthContext.Provider value={{ user, isLoading, login, register, logout, loadUser }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
