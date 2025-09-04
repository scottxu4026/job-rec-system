import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import api, { post, get } from '../services/api';

type User = {
  id: number;
  username: string;
  email: string;
  role: string;
};

type AuthContextValue = {
  user: User | null;
  isAuthenticated: boolean;
  login: (identifier: string, password: string) => Promise<void>;
  logout: () => void;
  refresh: () => Promise<void>;
};

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [bootstrapped, setBootstrapped] = useState(false);

  const fetchMe = useCallback(async () => {
    try {
      const res = await get<{ status: string; message: string; data: User }>('/auth/me');
      setUser(res.data.data);
    } catch (err) {
      setUser(null);
    }
  }, []);

  useEffect(() => {
    // Bootstrap from stored token
    const token = localStorage.getItem('auth_token');
    if (token) {
      fetchMe().finally(() => setBootstrapped(true));
    } else {
      setBootstrapped(true);
    }
  }, [fetchMe]);

  const login = useCallback(async (identifier: string, password: string) => {
    const res = await post<{ status: string; message: string; data: { token: string; expiresAt: number; user: User } }>(
      '/auth/login',
      { usernameOrEmail: identifier, password }
    );
    const { token, user } = res.data.data;
    localStorage.setItem('auth_token', token);
    setUser(user);
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('auth_token');
    setUser(null);
    if (typeof window !== 'undefined') {
      window.location.href = '/login';
    }
  }, []);

  const refresh = useCallback(async () => {
    await fetchMe();
  }, [fetchMe]);

  const value = useMemo<AuthContextValue>(() => ({
    user,
    isAuthenticated: !!user,
    login,
    logout,
    refresh,
  }), [user, login, logout, refresh]);

  if (!bootstrapped) return null;

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = (): AuthContextValue => {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
};


