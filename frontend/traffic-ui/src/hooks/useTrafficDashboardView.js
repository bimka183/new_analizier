import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ITEMS_PER_PAGE } from "../constants/trafficApp";
import { buildThreatSummary } from "../utils/threatSummary";
import { getAnomaly } from "../utils/traffic";
import {
  aggregateAnomaliesByType,
  aggregateTrafficBySourceIP,
  aggregateTrafficByTimeSlot,
} from "../utils/trafficAggregations";
import { groupTrafficRows } from "../utils/groupTrafficRows";
import { sortTrafficGroups } from "../utils/trafficTableSort";
import { useDebounce } from "./useDebounce";

export function useTrafficDashboardView(allData, options = {}) {
  const { tableBaseOrder = "chronological", fetchFilteredFn } = options;
  const isServerMode = typeof fetchFilteredFn === "function";

  const [filterSource, setFilterSource] = useState("");
  const [filterDestination, setFilterDestination] = useState("");
  const [filterPort, setFilterPort] = useState("");
  const [filterAnomaly, setFilterAnomaly] = useState("");
  const [filterProtocol, setFilterProtocol] = useState("");
  const [filterFlags, setFilterFlags] = useState([]);
  const [itemsPerPage, setItemsPerPage] = useState(ITEMS_PER_PAGE);
  const [currentPage, setCurrentPage] = useState(1);
  const [tableSort, setTableSort] = useState({
    column: null,
    direction: null,
  });

  const [serverFilteredData, setServerFilteredData] = useState(null);
  const fetchIdRef = useRef(0);
  const prevAllDataLenRef = useRef(allData.length);

  const debouncedSource = useDebounce(filterSource);
  const debouncedDestination = useDebounce(filterDestination);
  const debouncedPort = useDebounce(filterPort);
  const debouncedAnomaly = useDebounce(filterAnomaly);
  const debouncedProtocol = useDebounce(filterProtocol);
  const debouncedFlags = useDebounce(filterFlags);

  useEffect(() => {
    if (!isServerMode) return;

    const hasFilters =
      debouncedSource || debouncedDestination || debouncedPort ||
      debouncedAnomaly || debouncedProtocol || debouncedFlags.length > 0;

    if (!hasFilters) {
      setServerFilteredData(null);
      return;
    }

    const id = ++fetchIdRef.current;
    fetchFilteredFn({
      source: debouncedSource,
      destination: debouncedDestination,
      port: debouncedPort,
      anomaly: debouncedAnomaly,
      protocol: debouncedProtocol,
      flags: debouncedFlags.join(","),
    }).then((rows) => {
      if (fetchIdRef.current === id) setServerFilteredData(rows);
    });
  }, [
    isServerMode,
    fetchFilteredFn,
    debouncedSource,
    debouncedDestination,
    debouncedPort,
    debouncedAnomaly,
    debouncedProtocol,
    debouncedFlags,
  ]);

  const hasServerFiltersRef = useRef(false);
  hasServerFiltersRef.current = isServerMode && serverFilteredData !== null;

  useEffect(() => {
    const grew = allData.length > prevAllDataLenRef.current;
    prevAllDataLenRef.current = allData.length;

    if (!grew || !hasServerFiltersRef.current) return;

    const id = ++fetchIdRef.current;
    fetchFilteredFn({
      source: debouncedSource,
      destination: debouncedDestination,
      port: debouncedPort,
      anomaly: debouncedAnomaly,
      protocol: debouncedProtocol,
      flags: debouncedFlags.join(","),
    }).then((rows) => {
      if (fetchIdRef.current === id) setServerFilteredData(rows);
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [allData.length]);

  const matchesFilters = useCallback(
    (item) => {
      const srcOk =
        filterSource === "" ||
        String(item.source_ip ?? "").includes(filterSource);
      const dstOk =
        filterDestination === "" ||
        String(item.destination_ip ?? "").includes(filterDestination);
      const portNeedle = filterPort.trim();
      const portOk =
        portNeedle === "" ||
        String(item.source_port ?? "").includes(portNeedle) ||
        String(item.destination_port ?? "").includes(portNeedle);
      const anomalyOk =
        filterAnomaly === "" || getAnomaly(item) === filterAnomaly;
      const protocolOk =
        filterProtocol === "" || item.protocol === filterProtocol;
      const itemFlags = String(item.flags ?? "");
      const flagsOk =
        filterFlags.length === 0 ||
        filterFlags.every((f) => itemFlags.includes(f));
      return srcOk && dstOk && portOk && anomalyOk && protocolOk && flagsOk;
    },
    [filterAnomaly, filterDestination, filterFlags, filterPort, filterProtocol, filterSource]
  );

  const filteredChartData = useMemo(() => {
    if (isServerMode) {
      return serverFilteredData !== null ? serverFilteredData : allData;
    }
    return allData.filter((item) => matchesFilters(item));
  }, [isServerMode, serverFilteredData, allData, matchesFilters]);

  useEffect(() => {
    setCurrentPage(1);
  }, [filterAnomaly, filterDestination, filterFlags, filterPort, filterProtocol, filterSource, itemsPerPage]);

  const trafficTableGroups = useMemo(
    () => groupTrafficRows(filteredChartData),
    [filteredChartData]
  );

  const baseOrderedTableGroups = useMemo(() => {
    if (tableBaseOrder === "newest") {
      return [...trafficTableGroups].reverse();
    }
    return trafficTableGroups;
  }, [trafficTableGroups, tableBaseOrder]);

  const orderedTrafficTableGroups = useMemo(() => {
    if (!tableSort.column || !tableSort.direction) {
      return baseOrderedTableGroups;
    }
    return sortTrafficGroups(
      baseOrderedTableGroups,
      tableSort.column,
      tableSort.direction
    );
  }, [baseOrderedTableGroups, tableSort.column, tableSort.direction]);

  const totalPages = Math.ceil(orderedTrafficTableGroups.length / itemsPerPage);

  const paginatedTableGroups = useMemo(
    () =>
      orderedTrafficTableGroups.slice(
        (currentPage - 1) * itemsPerPage,
        currentPage * itemsPerPage
      ),
    [currentPage, itemsPerPage, orderedTrafficTableGroups]
  );

  useEffect(() => {
    setCurrentPage(1);
  }, [tableSort.column, tableSort.direction]);
  const paginatedData = paginatedTableGroups;

  const trafficByIP = useMemo(
    () => aggregateTrafficBySourceIP(filteredChartData),
    [filteredChartData]
  );

  const anomaliesCount = useMemo(
    () => aggregateAnomaliesByType(filteredChartData),
    [filteredChartData]
  );

  const trafficByTime = useMemo(
    () => aggregateTrafficByTimeSlot(filteredChartData),
    [filteredChartData]
  );

  const threatSummary = useMemo(
    () => buildThreatSummary(filteredChartData),
    [filteredChartData]
  );

  const clearFilters = useCallback(() => {
    setFilterSource("");
    setFilterDestination("");
    setFilterPort("");
    setFilterAnomaly("");
    setFilterProtocol("");
    setFilterFlags([]);
  }, []);

  const cycleTableSort = useCallback((columnKey) => {
    setTableSort((prev) => {
      if (prev.column !== columnKey) {
        return { column: columnKey, direction: "asc" };
      }
      if (prev.direction === "asc") {
        return { column: columnKey, direction: "desc" };
      }
      if (prev.direction === "desc") {
        return { column: null, direction: null };
      }
      return { column: columnKey, direction: "asc" };
    });
  }, []);

  return {
    filterSource,
    setFilterSource,
    filterDestination,
    setFilterDestination,
    filterPort,
    setFilterPort,
    filterAnomaly,
    setFilterAnomaly,
    filterProtocol,
    setFilterProtocol,
    filterFlags,
    setFilterFlags,
    clearFilters,
    sortColumn: tableSort.column,
    sortDirection: tableSort.direction,
    cycleTableSort,
    itemsPerPage,
    setItemsPerPage,
    currentPage,
    setCurrentPage,
    filteredChartData,
    totalPages,
    paginatedData,
    trafficTableGroups,
    paginatedTableGroups,
    trafficByIP,
    anomaliesCount,
    trafficByTime,
    threatSummary,
  };
}
