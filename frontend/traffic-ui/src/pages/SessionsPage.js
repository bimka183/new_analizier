import React from "react";
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
  onFilterSourceChange,
  onFilterDestinationChange,
  onFilterPortChange,
  onFilterAnomalyChange,
  onClearFilters,
  currentPage,
  totalPages,
  totalRows,
  itemsPerPage,
  onItemsPerPageChange,
  onPrevPage,
  onNextPage,
  loading = false,
  fetchError = null,
}) {
  return (
    <section className="sessions-page">
      <h2>Sessions</h2>
      <p className="sessions-page__lead">
        Traffic rows grouped by time window (newest first). Filters and
        pagination are loaded from the server on each change.
      </p>

      {loading ? (
        <p className="sessions-page__status" role="status">
          Loading traffic…
        </p>
      ) : null}
      {fetchError ? (
        <p className="sessions-page__status sessions-page__status--error" role="alert">
          Failed to load traffic. Check that the backend is running.
        </p>
      ) : null}

      <div className="app__controls sessions-page__controls">
        <TrafficFilters
          filterSource={filterSource}
          filterDestination={filterDestination}
          filterPort={filterPort}
          filterAnomaly={filterAnomaly}
          onFilterSourceChange={onFilterSourceChange}
          onFilterDestinationChange={onFilterDestinationChange}
          onFilterPortChange={onFilterPortChange}
          onFilterAnomalyChange={onFilterAnomalyChange}
          onClearFilters={onClearFilters}
        />
        <TrafficTable
          groups={paginatedTableGroups}
          sortColumn={sortColumn}
          sortDirection={sortDirection}
          onSortColumn={onSortColumn}
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
