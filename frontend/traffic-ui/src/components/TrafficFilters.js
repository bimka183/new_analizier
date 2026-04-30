import React from "react";

function TrafficFilters({
  filterIP,
  filterAnomaly,
  onFilterIPChange,
  onFilterAnomalyChange,
}) {
  return (
    <div className="app__controls">
      <input
        placeholder="Filter by IP"
        value={filterIP}
        onChange={(event) => onFilterIPChange(event.target.value)}
      />

      <select
        value={filterAnomaly}
        onChange={(event) => onFilterAnomalyChange(event.target.value)}
      >
        <option value="">All</option>
        <option value="DoS/DDoS Attack">DoS/DDoS</option>
        <option value="Network Overload">Overload</option>
        <option value="Network/Port Scanning">Port Scanning</option>
        <option value="Worm Activity">Worm</option>
        <option value="Confirmed Virus Activity">Virus</option>
        <option value="Point-to-Multipoint">P2MP</option>
        <option value="Flow Switching">Flow Switching</option>
      </select>
    </div>
  );
}

export default TrafficFilters;
