import { useCallback, useEffect, useState } from "react";
import { API_BASE_URL, ITEMS_PER_PAGE } from "../constants/trafficApp";

export function useServerPaginatedTraffic(uploadId) {
  const [pageRows, setPageRows] = useState([]);
  const [totalRows, setTotalRows] = useState(0);
  const [currentPage, setCurrentPage] = useState(1);
  const [itemsPerPage, setItemsPerPage] = useState(ITEMS_PER_PAGE);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setCurrentPage(1);
  }, [uploadId, itemsPerPage]);

  useEffect(() => {
    if (!uploadId) {
      setPageRows([]);
      setTotalRows(0);
      return;
    }

    let cancelled = false;
    setLoading(true);

    fetch(
      `${API_BASE_URL}/api/traffic?upload_id=${uploadId}&page=${currentPage}&limit=${itemsPerPage}`
    )
      .then((res) => res.json())
      .then((json) => {
        if (cancelled) return;
        setPageRows(json.data ?? []);
        setTotalRows(json.total ?? 0);
      })
      .catch(() => {
        if (cancelled) return;
        setPageRows([]);
        setTotalRows(0);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [uploadId, currentPage, itemsPerPage]);

  const totalPages = Math.max(1, Math.ceil(totalRows / itemsPerPage));

  const goNext = useCallback(() => {
    setCurrentPage((p) => Math.min(p + 1, totalPages));
  }, [totalPages]);

  const goPrev = useCallback(() => {
    setCurrentPage((p) => Math.max(p - 1, 1));
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
    goNext,
    goPrev,
  };
}
