import { API_BASE_URL } from "../constants/trafficApp";
import { getAdminAuthorizationHeader } from "../auth/sessionPersistence";

function requireAdminAuthHeader() {
  const auth = getAdminAuthorizationHeader();
  if (!auth) {
    throw new Error(
      "Нет учётных данных для админ-API: войдите снова в этой вкладке (пароль хранится только до её закрытия)."
    );
  }
  return { Authorization: auth };
}

async function parseJsonSafe(resp) {
  try {
    return await resp.json();
  } catch {
    return {};
  }
}

/**
 * DELETE /api/admin/traffic — удалить все записи трафика.
 * @returns {Promise<{ status?: string, error?: string }>}
 */
export async function deleteAllTraffic() {
  const resp = await fetch(`${API_BASE_URL}/api/admin/traffic`, {
    method: "DELETE",
    headers: requireAdminAuthHeader(),
  });
  const data = await parseJsonSafe(resp);
  if (!resp.ok) {
    throw new Error(
      typeof data.error === "string" ? data.error : `Ошибка ${resp.status}`
    );
  }
  return data;
}

/**
 * POST /api/admin/reset — сброс БД к состоянию по умолчанию.
 * @returns {Promise<{ status?: string, error?: string }>}
 */
export async function resetDatabase() {
  const resp = await fetch(`${API_BASE_URL}/api/admin/reset`, {
    method: "POST",
    headers: requireAdminAuthHeader(),
  });
  const data = await parseJsonSafe(resp);
  if (!resp.ok) {
    throw new Error(
      typeof data.error === "string" ? data.error : `Ошибка ${resp.status}`
    );
  }
  return data;
}
