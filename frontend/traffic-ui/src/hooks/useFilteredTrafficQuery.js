import { useCallback, useEffect, useRef, useState } from "react";
import { API_BASE_URL, ITEMS_PER_PAGE } from "../constants/trafficApp";
import { buildTrafficApiUrl } from "../utils/buildTrafficApiUrl";
import { useDebounce } from "./useDebounce";

const FILTER_DEBOUNCE_MS = 300;

/**
 * Fetches traffic from GET /api/traffic with server-side filters and pagination.
 * Re-fetches when filters (debounced text fields), anomaly, page, or page size change.
 */
export function useFilteredTrafficQuery({ enabled = true, uploadId = "" } = {}) {
  const [filterSource, setFilterSource] = useState("");
  const [filterDestination, setFilterDestination] = useState("");
  const [filterPort, setFilterPort] = useState("");
  const [filterAnomaly, setFilterAnomaly] = useState("");
  const [pageRows, setPageRows] = useState([]);
  const [totalRows, setTotalRows] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(ITEMS_PER_PAGE);
  const [loading, setLoading] = useState(false);
  const [fetchError, setFetchError] = useState(null);

  const debouncedSource = useDebounce(filterSource, FILTER_DEBOUNCE_MS);
  const debouncedDestination = useDebounce(filterDestination, FILTER_DEBOUNCE_MS);
  const debouncedPort = useDebounce(filterPort, FILTER_DEBOUNCE_MS);

  const apiBaseRef = useRef(API_BASE_URL);
  const requestIdRef = useRef(0);

  useEffect(() => {
    setCurrentPage(1);
  }, [
    debouncedSource,
    debouncedDestination,
    debouncedPort,
    filterAnomaly,
    itemsPerPage,
    uploadId,
  ]);

  const loadTraffic = useCallback(async () => {
    if (!enabled) {
      setPageRows([]);
      setTotalRows(0);
      setLoading(false);
      return;
    }

    const requestId = ++requestIdRef.current;
    setLoading(true);
    setFetchError(null);

    try {
      const url = buildTrafficApiUrl(apiBaseRef.current, {
        page: currentPage,
        limit: itemsPerPage,
        source_ip: debouncedSource,
        destination_ip: debouncedDestination,
        port: debouncedPort,
        anomaly: filterAnomaly,
        upload_id: uploadId,
      });
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`traffic request failed (${response.status})`);
      }
      const json = await response.json();
      if (requestId !== requestIdRef.current) return;
      setPageRows(json.data ?? []);
      setTotalRows(json.total ?? 0);
    } catch (error) {
      if (requestId !== requestIdRef.current) return;
      setPageRows([]);
      setTotalRows(0);
      setFetchError(error);
    } finally {
      if (requestId === requestIdRef.current) {
        setLoading(false);
      }
    }
  }, [
    enabled,
    currentPage,
    itemsPerPage,
    debouncedSource,
    debouncedDestination,
    debouncedPort,
    filterAnomaly,
    uploadId,
  ]);

  useEffect(() => {
    loadTraffic();
  }, [loadTraffic]);

  const totalPages = Math.max(1, Math.ceil(totalRows / itemsPerPage));

  const clearFilters = useCallback(() => {
    setFilterSource("");
    setFilterDestination("");
    setFilterPort("");
    setFilterAnomaly("");
  }, []);

  const goNext = useCallback(() => {
    setCurrentPage((page) => Math.min(page + 1, totalPages));
  }, [totalPages]);

  const goPrev = useCallback(() => {
    setCurrentPage((page) => Math.max(page - 1, 1));
  }, []);

  return {
    pageRows,
    totalRows,
    totalPages,
    currentPage,
    setCurrentPage,
    itemsPerPage,
    setItemsPerPage,
    loading,
    fetchError,
    refetch: loadTraffic,
    filterSource,
    setFilterSource,
    filterDestination,
    setFilterDestination,
    filterPort,
    setFilterPort,
    filterAnomaly,
    setFilterAnomaly,
    clearFilters,
    goNext,
    goPrev,
  };
}
