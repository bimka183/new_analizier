import {
  AUTH_SECRET_STORAGE_KEY,
  AUTH_SESSION_COOKIE_NAME,
  AUTH_SESSION_MAX_AGE_DAYS,
} from "../constants/authSession";

function getCookieValue(name) {
  if (typeof document === "undefined") return null;
  const prefix = `${name}=`;
  const parts = document.cookie.split(";").map((p) => p.trim());
  for (const part of parts) {
    if (part.startsWith(prefix)) {
      return decodeURIComponent(part.slice(prefix.length));
    }
  }
  return null;
}

/**
 * @returns {{ username: string, role: string } | null}
 */
export function readSessionFromCookie() {
  const raw = getCookieValue(AUTH_SESSION_COOKIE_NAME);
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    if (
      parsed &&
      typeof parsed.username === "string" &&
      typeof parsed.role === "string"
    ) {
      return { username: parsed.username, role: parsed.role };
    }
  } catch {
    return null;
  }
  return null;
}

/**
 * @param {{ username: string, role: string }} session
 */
export function writeSessionCookie(session) {
  if (typeof document === "undefined") return;
  const maxAge = AUTH_SESSION_MAX_AGE_DAYS * 24 * 60 * 60;
  const value = encodeURIComponent(
    JSON.stringify({ username: session.username, role: session.role })
  );
  document.cookie = `${AUTH_SESSION_COOKIE_NAME}=${value}; path=/; max-age=${maxAge}; SameSite=Lax`;
}

export function clearSessionCookie() {
  if (typeof document === "undefined") return;
  document.cookie = `${AUTH_SESSION_COOKIE_NAME}=; path=/; max-age=0; SameSite=Lax`;
}

export function writeAuthSecret(password) {
  if (typeof sessionStorage === "undefined") return;
  sessionStorage.setItem(AUTH_SECRET_STORAGE_KEY, password);
}

export function readAuthSecret() {
  if (typeof sessionStorage === "undefined") return null;
  return sessionStorage.getItem(AUTH_SECRET_STORAGE_KEY);
}

export function clearAuthSecret() {
  if (typeof sessionStorage === "undefined") return;
  sessionStorage.removeItem(AUTH_SECRET_STORAGE_KEY);
}

/**
 * Matches backend admin middleware: `Authorization: username:password`.
 * @returns {string | null}
 */
export function getAdminAuthorizationHeader() {
  const session = readSessionFromCookie();
  const password = readAuthSecret();
  if (!session?.username || password == null || password === "") return null;
  return `${session.username}:${password}`;
}
