import React, { useEffect, useRef, useState } from "react";
import Button from "../ui/button/Button";

const ALL_FLAGS = ["SYN", "ACK", "FIN", "RST", "PSH", "URG"];

function FlagsDropdown({ filterFlags, onFilterFlagsChange }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return;
    const onClickOutside = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener("mousedown", onClickOutside);
    return () => document.removeEventListener("mousedown", onClickOutside);
  }, [open]);

  const handleToggle = (flag) => {
    const next = filterFlags.includes(flag)
      ? filterFlags.filter((f) => f !== flag)
      : [...filterFlags, flag];
    onFilterFlagsChange(next);
  };

  const label =
    filterFlags.length === 0
      ? "Flags"
      : filterFlags.join(", ");

  return (
    <div className="flags-dropdown" ref={ref}>
      <button
        type="button"
        className="flags-dropdown__trigger"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        aria-haspopup="listbox"
      >
        <span className="flags-dropdown__label">{label}</span>
        <span className="flags-dropdown__arrow">{open ? "\u25B2" : "\u25BC"}</span>
      </button>
      {open && (
        <div className="flags-dropdown__menu" role="listbox" aria-label="Select TCP flags">
          {ALL_FLAGS.map((flag) => (
            <label key={flag} className="flags-dropdown__item">
              <input
                type="checkbox"
                checked={filterFlags.includes(flag)}
                onChange={() => handleToggle(flag)}
              />
              {flag}
            </label>
          ))}
        </div>
      )}
    </div>
  );
}

function TrafficFilters({
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
        aria-label="Filter by protocol"
        value={filterProtocol}
        onChange={(event) => onFilterProtocolChange(event.target.value)}
      >
        <option value="">All protocols</option>
        <option value="TCP">TCP</option>
        <option value="UDP">UDP</option>
        <option value="Other">Other</option>
      </select>

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

      <FlagsDropdown
        filterFlags={filterFlags}
        onFilterFlagsChange={onFilterFlagsChange}
      />

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
