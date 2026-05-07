import React from "react";
import Button from "../ui/button/Button";

function TrafficFilters({
  filterSource,
  filterDestination,
  filterPort,
  filterAnomaly,
  onFilterSourceChange,
  onFilterDestinationChange,
  onFilterPortChange,
  onFilterAnomalyChange,
  onClearFilters,
}) {
  return (
    <div className="app__filters">
      <input
        type="search"
        placeholder="Source"
        aria-label="Filter by source IP"
        value={filterSource}
        onChange={(event) => onFilterSourceChange(event.target.value)}
      />

      <input
        type="search"
        placeholder="Destination"
        aria-label="Filter by destination IP"
        value={filterDestination}
        onChange={(event) => onFilterDestinationChange(event.target.value)}
      />

      <input
        type="search"
        inputMode="numeric"
        placeholder="Port"
        aria-label="Filter by source or destination port"
        value={filterPort}
        onChange={(event) => onFilterPortChange(event.target.value)}
      />

      <select
        aria-label="Filter by anomaly type"
        value={filterAnomaly}
        onChange={(event) => onFilterAnomalyChange(event.target.value)}
      >
        <option value="">All anomalies</option>
        <option value="DoS/DDoS Attack">DoS/DDoS</option>
        <option value="Network Overload">Overload</option>
        <option value="Network/Port Scanning">Port Scanning</option>
        <option value="Worm Activity">Worm</option>
        <option value="Confirmed Virus Activity">Virus</option>
        <option value="Point-to-Multipoint">P2MP</option>
        <option value="Flow Switching">Flow Switching</option>
      </select>

      <Button
        type="button"
        className="app__filters-clear"
        onClick={onClearFilters}
      >
        Clear
      </Button>
    </div>
  );
}

export default TrafficFilters;
