import React from "react";
import { useLocation, useNavigate } from "react-router-dom";
import TrafficFilters from "../components/TrafficFilters";
import TrafficPagination from "../components/TrafficPagination";
import TrafficTable from "../components/TrafficTable";
import "./SessionsPage.scss";

function SessionsPage({
  paginatedTableGroups = [],
  sortColumn,
  sortDirection,
  onSortColumn,
  filterSource,
  filterDestination,
  filterPort,
  filterAnomaly,
  filterProtocol,
  filterFlags,
  onFilterSourceChange,
  onFilterDestinationChange,
  onFilterPortChange,
  onFilterAnomalyChange,
  onFilterProtocolChange,
  onFilterFlagsChange,
  onClearFilters,
  currentPage,
  totalPages,
  totalRows,
  itemsPerPage,
  onItemsPerPageChange,
  onPrevPage,
  onNextPage,
}) {
  const location = useLocation();
  const navigate = useNavigate();

  const autoDetailPacketsRef = React.useRef(
    location.state?.autoDetailPackets || null
  );

  React.useEffect(() => {
    if (location.state?.autoDetailPackets) {
      navigate(location.pathname, { replace: true, state: {} });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <section className="sessions-page">
      <h2>Sessions</h2>
      <p className="sessions-page__lead">
        Traffic rows grouped by time window (newest first). Filters apply to the
        same dataset as on the dashboard.
      </p>

      <div className="app__controls sessions-page__controls">
        <TrafficFilters
          filterSource={filterSource}
          filterDestination={filterDestination}
          filterPort={filterPort}
          filterAnomaly={filterAnomaly}
          filterProtocol={filterProtocol}
          filterFlags={filterFlags}
          onFilterSourceChange={onFilterSourceChange}
          onFilterDestinationChange={onFilterDestinationChange}
          onFilterPortChange={onFilterPortChange}
          onFilterAnomalyChange={onFilterAnomalyChange}
          onFilterProtocolChange={onFilterProtocolChange}
          onFilterFlagsChange={onFilterFlagsChange}
          onClearFilters={onClearFilters}
        />
        <TrafficTable
          groups={paginatedTableGroups}
          sortColumn={sortColumn}
          sortDirection={sortDirection}
          onSortColumn={onSortColumn}
          enableDetailsForSingleRow
          initialModalPackets={autoDetailPacketsRef.current}
        />
        <TrafficPagination
          currentPage={currentPage}
          totalPages={totalPages}
          totalRows={totalRows}
          itemsPerPage={itemsPerPage}
          onItemsPerPageChange={onItemsPerPageChange}
          onPrev={onPrevPage}
          onNext={onNextPage}
        />
      </div>
    </section>
  );
}

export default SessionsPage;
