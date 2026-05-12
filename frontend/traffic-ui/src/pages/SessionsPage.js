import React from "react";
import { useLocation, useNavigate } from "react-router-dom";
import TrafficFilters from "../components/TrafficFilters";
import TrafficPagination from "../components/TrafficPagination";
import TrafficTable from "../components/TrafficTable";
import { useTrafficDashboardView } from "../hooks/useTrafficDashboardView";
import "./SessionsPage.scss";

function SessionsPage({ allData = [], fetchWithFilters }) {
  const location = useLocation();
  const navigate = useNavigate();

  const autoDetailPacketsRef = React.useRef(
    location.state?.autoDetailPackets || null
  );
  const initialFiltersRef = React.useRef(
    location.state?.initialFilters || null
  );

  React.useEffect(() => {
    if (location.state?.autoDetailPackets || location.state?.initialFilters) {
      navigate(location.pathname, { replace: true, state: {} });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const {
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
    sortColumn,
    sortDirection,
    cycleTableSort,
    itemsPerPage,
    setItemsPerPage,
    currentPage,
    setCurrentPage,
    totalPages,
    trafficTableGroups,
    paginatedTableGroups,
  } = useTrafficDashboardView(allData, {
    tableBaseOrder: "newest",
    fetchFilteredFn: fetchWithFilters,
  });

  React.useEffect(() => {
    const f = initialFiltersRef.current;
    if (!f) return;
    if (f.source) setFilterSource(f.source);
    if (f.destination) setFilterDestination(f.destination);
    if (f.protocol) setFilterProtocol(f.protocol);
    if (f.anomaly) setFilterAnomaly(f.anomaly);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <section className="sessions-page">
      <h2>Sessions</h2>
      <p className="sessions-page__lead">
        Traffic rows grouped by time window (newest first). Filters apply only
        to this view.
      </p>

      <div className="app__controls sessions-page__controls">
        <TrafficFilters
          filterSource={filterSource}
          filterDestination={filterDestination}
          filterPort={filterPort}
          filterAnomaly={filterAnomaly}
          filterProtocol={filterProtocol}
          filterFlags={filterFlags}
          onFilterSourceChange={setFilterSource}
          onFilterDestinationChange={setFilterDestination}
          onFilterPortChange={setFilterPort}
          onFilterAnomalyChange={setFilterAnomaly}
          onFilterProtocolChange={setFilterProtocol}
          onFilterFlagsChange={setFilterFlags}
          onClearFilters={clearFilters}
        />
        <TrafficTable
          groups={paginatedTableGroups}
          sortColumn={sortColumn}
          sortDirection={sortDirection}
          onSortColumn={cycleTableSort}
          enableDetailsForSingleRow
          initialModalPackets={autoDetailPacketsRef.current}
        />
        <TrafficPagination
          currentPage={currentPage}
          totalPages={totalPages || 1}
          totalRows={trafficTableGroups.length}
          itemsPerPage={itemsPerPage}
          onItemsPerPageChange={setItemsPerPage}
          onPrev={() => setCurrentPage((p) => p - 1)}
          onNext={() => setCurrentPage((p) => p + 1)}
        />
      </div>
    </section>
  );
}

export default SessionsPage;
