/**
 * Builds GET /api/traffic URL with pagination and server-side filter query params.
 */
export function buildTrafficApiUrl(baseUrl, query = {}) {
  const params = new URLSearchParams();
  params.set("page", String(query.page ?? 1));
  params.set("limit", String(query.limit ?? 10));

  if (query.source_ip) {
    params.set("source_ip", query.source_ip);
  }
  if (query.destination_ip) {
    params.set("destination_ip", query.destination_ip);
  }
  const port = String(query.port ?? "").trim();
  if (port) {
    params.set("port", port);
  }
  if (query.anomaly) {
    params.set("anomaly", query.anomaly);
  }
  if (query.protocol) {
    params.set("protocol", query.protocol);
  }
  if (query.upload_id) {
    params.set("upload_id", query.upload_id);
  }

  return `${baseUrl}/api/traffic?${params.toString()}`;
}
