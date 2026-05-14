import { API_BASE_URL } from "../constants/trafficApp";

export async function fetchUploads() {
  const resp = await fetch(`${API_BASE_URL}/api/uploads`);
  if (!resp.ok) throw new Error(`Failed to fetch uploads: ${resp.status}`);
  const json = await resp.json();
  if (Array.isArray(json)) {
    return json;
  }
  return json.data ?? [];
}

export async function fetchUploadById(id) {
  const resp = await fetch(`${API_BASE_URL}/api/uploads/${id}`);
  if (!resp.ok) throw new Error(`Failed to fetch upload: ${resp.status}`);
  return resp.json();
}

export async function deleteUpload(id) {
  const resp = await fetch(`${API_BASE_URL}/api/uploads/${id}`, {
    method: "DELETE",
  });
  if (!resp.ok) throw new Error(`Failed to delete upload: ${resp.status}`);
  return resp.json();
}
