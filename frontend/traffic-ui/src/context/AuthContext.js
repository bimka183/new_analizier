import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { loginRequest } from "../api/authApi";
import {
  clearAuthSecret,
  clearSessionCookie,
  readSessionFromCookie,
  writeAuthSecret,
  writeSessionCookie,
} from "../auth/sessionPersistence";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);

  useEffect(() => {
    const fromCookie = readSessionFromCookie();
    if (fromCookie) {
      setUser({ username: fromCookie.username, role: fromCookie.role });
    }
  }, []);

  const login = useCallback(async ({ username, password }) => {
    const trimmedUser = username.trim();
    const data = await loginRequest({
      username: trimmedUser,
      password,
    });
    writeSessionCookie({ username: data.username, role: data.role });
    writeAuthSecret(password);
    setUser({ username: data.username, role: data.role });
  }, []);

  const logout = useCallback(() => {
    clearSessionCookie();
    clearAuthSecret();
    setUser(null);
  }, []);

  const value = useMemo(
    () => ({
      user,
      login,
      logout,
      isAuthenticated: Boolean(user),
    }),
    [user, login, logout]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return ctx;
}
