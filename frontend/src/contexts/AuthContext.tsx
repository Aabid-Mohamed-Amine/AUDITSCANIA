"use client";

import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { authApi, tokenStore, type User } from "@/lib/api";

interface AuthContextValue {
  user: User | null;
  token: string | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (email: string, password: string, rememberMe?: boolean) => Promise<void>;
  register: (email: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const queryClient = useQueryClient();

  // Restore session on mount
  useEffect(() => {
    const stored = tokenStore.getAccess();
    if (stored) {
      setToken(stored);
      authApi
        .me(stored)
        .then(setUser)
        .catch(() => {
          tokenStore.clear();
          setToken(null);
        })
        .finally(() => setIsLoading(false));
    } else {
      setIsLoading(false);
    }
  }, []);

  const login = async (email: string, password: string, rememberMe = false) => {
    tokenStore.setRemember(rememberMe);
    const data = await authApi.login(email, password);
    tokenStore.set(data.access_token, data.refresh_token);
    setToken(data.access_token);
    // Use user from login response if present (new backend), fallback to /me (old backend)
    const me = data.user ?? await authApi.me(data.access_token);
    setUser(me);
  };

  const register = async (email: string, password: string) => {
    await authApi.register(email, password);
  };

  const logout = () => {
    const currentToken = token;
    const currentRefresh = tokenStore.getRefresh();
    if (currentToken) {
      // Fire-and-forget — local cleanup always happens regardless
      authApi.logout(currentToken, currentRefresh).catch(() => {});
    }
    tokenStore.clear();
    setToken(null);
    setUser(null);
    queryClient.clear();
  };

  return (
    <AuthContext.Provider
      value={{ user, token, isLoading, isAuthenticated: !!user, login, register, logout }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
