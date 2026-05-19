import { API_BASE_URL, KNOWN_THREAT_TYPES } from "../constants/trafficApp";
import { buildTrafficApiUrl } from "../utils/buildTrafficApiUrl";

export function parseUploadSummary(raw) {
  if (!raw) return null;
  if (typeof raw === "object") return raw;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export async function fetchAllTrafficByUploadId(uploadId, { pageSize = 1000 } = {}) {
  const id = String(uploadId ?? "").trim();
  if (!id) {
    return [];
  }

  const accumulated = [];
  let page = 1;
  let total = Infinity;

  while (accumulated.length < total) {
    const url = buildTrafficApiUrl(API_BASE_URL, {
      page,
      limit: pageSize,
      upload_id: id,
    });
    const resp = await fetch(url);
    if (!resp.ok) {
      throw new Error(`Failed to fetch traffic for upload ${id}: ${resp.status}`);
    }
    const json = await resp.json();
    const batch = json.data ?? [];
    total = Number(json.total ?? batch.length);
    accumulated.push(...batch);

    if (batch.length === 0 || accumulated.length >= total) {
      break;
    }
    page += 1;
  }

  return accumulated;
}

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

async function fetchTrafficTotalForUpload(uploadId, query = {}) {
  const url = buildTrafficApiUrl(API_BASE_URL, {
    page: 1,
    limit: 1,
    upload_id: uploadId,
    ...query,
  });
  const resp = await fetch(url);
  if (!resp.ok) {
    throw new Error(`Failed to fetch traffic count: ${resp.status}`);
  }
  const json = await resp.json();
  return Number(json.total ?? 0);
}

async function fetchOldestFlowTimestamp(uploadId, totalFlows) {
  if (!totalFlows) return null;
  const url = buildTrafficApiUrl(API_BASE_URL, {
    page: totalFlows,
    limit: 1,
    upload_id: uploadId,
  });
  const resp = await fetch(url);
  if (!resp.ok) return null;
  const json = await resp.json();
  return json.data?.[0]?.timestamp ?? null;
}

/**
 * Full Analysis + Threat summary for an upload without loading all flow rows.
 * Uses GET /api/uploads/:id and paginated GET /api/traffic (count-only requests).
 */
export async function fetchUploadReportOverview(uploadId) {
  const id = String(uploadId ?? "").trim();
  if (!id) {
    throw new Error("upload id is required");
  }

  const upload = await fetchUploadById(id);
  const summaryMeta = parseUploadSummary(upload.summary);
  const totalFlows = Number(upload.flow_count ?? 0);

  const [oldestTimestamp, ...threatTotals] = await Promise.all([
    fetchOldestFlowTimestamp(id, totalFlows),
    ...KNOWN_THREAT_TYPES.map((anomaly) =>
      fetchTrafficTotalForUpload(id, { anomaly }).then((value) => ({
        name: anomaly,
        value,
      }))
    ),
  ]);

  const threatSummary = threatTotals;
  const totalPackets = summaryMeta?.packets ?? 0;

  return {
    upload,
    analysisSummary: {
      packets: totalPackets,
      flows: totalFlows,
      startTime: oldestTimestamp || upload.uploaded_at || "—",
      duration: "—",
    },
    threatSummary,
    threatRowsCount: totalFlows,
  };
}

export async function deleteUpload(id) {
  const resp = await fetch(`${API_BASE_URL}/api/uploads/${id}`, {
    method: "DELETE",
  });
  if (!resp.ok) throw new Error(`Failed to delete upload: ${resp.status}`);
  return resp.json();
}
