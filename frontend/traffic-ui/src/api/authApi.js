import { API_BASE_URL } from "../constants/trafficApp";

/**
 * @param {{ username: string, password: string }} credentials
 * @returns {Promise<{ status: string, username: string, role: string }>}
 */
export async function loginRequest({ username, password }) {
  const resp = await fetch(`${API_BASE_URL}/api/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  let data = {};
  try {
    data = await resp.json();
  } catch {
    data = {};
  }
  if (!resp.ok) {
    const message =
      typeof data.error === "string" ? data.error : `Login failed (${resp.status})`;
    throw new Error(message);
  }
  return data;
}
