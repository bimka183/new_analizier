import { useCallback, useEffect, useMemo, useState } from "react";
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

export function useTrafficDashboardView(allData, options = {}) {
  const { tableBaseOrder = "chronological" } = options;
  const [filterSource, setFilterSource] = useState("");
  const [filterDestination, setFilterDestination] = useState("");
  const [filterPort, setFilterPort] = useState("");
  const [filterAnomaly, setFilterAnomaly] = useState("");
  const [itemsPerPage, setItemsPerPage] = useState(ITEMS_PER_PAGE);
  const [currentPage, setCurrentPage] = useState(1);
  const [tableSort, setTableSort] = useState({
    column: null,
    direction: null,
  });

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
      return srcOk && dstOk && portOk && anomalyOk;
    },
    [filterAnomaly, filterDestination, filterPort, filterSource]
  );

  const filteredChartData = useMemo(
    () => allData.filter((item) => matchesFilters(item)),
    [allData, matchesFilters]
  );

  useEffect(() => {
    setCurrentPage(1);
  }, [filterAnomaly, filterDestination, filterPort, filterSource, itemsPerPage]);

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
