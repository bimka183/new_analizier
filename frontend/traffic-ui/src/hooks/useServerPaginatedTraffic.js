import { useFilteredTrafficQuery } from "./useFilteredTrafficQuery";

/** Server-paginated traffic for a single upload (e.g. file analysis). */
export function useServerPaginatedTraffic(uploadId) {
  return useFilteredTrafficQuery({
    enabled: Boolean(uploadId),
    uploadId: uploadId ?? "",
  });
}
