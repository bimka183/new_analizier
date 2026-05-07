import React, { useMemo, useState } from "react";
import PacketDetailModal from "../ui/packet-detail-modal/PacketDetailModal";
import { getTrafficGroupSummary } from "../utils/groupTrafficRows";
import { getAnomalyBadgeClassName } from "../utils/traffic";
import "./TrafficTable.scss";

const TABLE_COLUMNS = [
  { key: "time", label: "Time" },
  { key: "anomaly", label: "Anomaly" },
  { key: "source", label: "Source" },
  { key: "destination", label: "Destination" },
  { key: "protocol", label: "Protocol" },
  { key: "srcPort", label: "Src Port" },
  { key: "dstPort", label: "Dst Port" },
  { key: "packets", label: "Packets" },
  { key: "volume", label: "Volume" },
  { key: "flags", label: "Flags" },
];

function SortColumnHeader({
  columnKey,
  label,
  sortColumn,
  sortDirection,
  onSortColumn,
}) {
  const isActive = sortColumn === columnKey;
  const dir = isActive ? sortDirection : null;

  const ariaSort =
    !isActive || !dir ? "none" : dir === "asc" ? "ascending" : "descending";

  let ariaLabel = `Sort by ${label}`;
  if (isActive && dir === "asc") {
    ariaLabel = `${label}, sorted ascending. Activate for descending.`;
  } else if (isActive && dir === "desc") {
    ariaLabel = `${label}, sorted descending. Activate to clear sorting.`;
  } else {
    ariaLabel = `${label}, not sorted. Activate for ascending.`;
  }

  return (
    <th scope="col" className="traffic-table__th traffic-table__th--sortable" aria-sort={ariaSort}>
      <button
        type="button"
        className="traffic-table__sort-btn"
        onClick={() => onSortColumn(columnKey)}
        aria-label={ariaLabel}
      >
        <span className="traffic-table__sort-label">{label}</span>
        <span className="traffic-table__sort-icons" aria-hidden>
          <span
            className={`traffic-table__sort-chevron traffic-table__sort-chevron--up ${
              dir === "asc" ? "is-active" : ""
            }`}
          >
            ▲
          </span>
          <span
            className={`traffic-table__sort-chevron traffic-table__sort-chevron--down ${
              dir === "desc" ? "is-active" : ""
            }`}
          >
            ▼
          </span>
        </span>
      </button>
    </th>
  );
}

function TrafficTable({
  groups = [],
  sortColumn = null,
  sortDirection = null,
  onSortColumn,
  enableDetailsForSingleRow = false,
}) {
  const [modalPackets, setModalPackets] = useState(null);

  const headerCells = useMemo(() => {
    if (typeof onSortColumn === "function") {
      return TABLE_COLUMNS.map((col) => (
        <SortColumnHeader
          key={col.key}
          columnKey={col.key}
          label={col.label}
          sortColumn={sortColumn}
          sortDirection={sortDirection}
          onSortColumn={onSortColumn}
        />
      ));
    }
    return TABLE_COLUMNS.map((col) => (
      <th key={col.key} scope="col" className="traffic-table__th">
        {col.label}
      </th>
    ));
  }, [onSortColumn, sortColumn, sortDirection]);

  return (
    <>
      <table className="traffic-table">
        <thead>
          <tr>{headerCells}</tr>
        </thead>

        <tbody>
          {groups.map((group) => {
            const s = getTrafficGroupSummary(group.packets);
            const rowClass = s.count > 1 ? "traffic-table__row--grouped" : "";
            const anomalyClass = getAnomalyBadgeClassName(s.anomalyLabel);
            const isDetailsEnabled = enableDetailsForSingleRow || s.count > 1;
            const openDetails = () => {
              if (isDetailsEnabled) setModalPackets(group.packets);
            };

            return (
              <tr
                key={group.key}
                className={rowClass}
                onClick={openDetails}
                onKeyDown={(e) => {
                  if (isDetailsEnabled && (e.key === "Enter" || e.key === " ")) {
                    e.preventDefault();
                    openDetails();
                  }
                }}
                tabIndex={isDetailsEnabled ? 0 : undefined}
                role={isDetailsEnabled ? "button" : undefined}
                aria-label={
                  isDetailsEnabled
                    ? s.count > 1
                      ? "Open packet list for this group"
                      : "Open packet details"
                    : undefined
                }
              >
                <td>{s.timeLabel}</td>
                <td>
                  <span className={`traffic-table__anomaly-pill ${anomalyClass}`}>
                    {s.anomalyLabel}
                  </span>
                </td>
                <td>{s.sourceLabel}</td>
                <td>{s.destinationLabel}</td>
                <td>{s.protocolLabel}</td>
                <td>{s.srcPortLabel}</td>
                <td>{s.dstPortLabel}</td>
                <td>{s.idLabel}</td>
                <td>{s.volumeLabel}</td>
                <td>{s.flagsLabel}</td>
              </tr>
            );
          })}
        </tbody>
      </table>

      <PacketDetailModal
        open={Boolean(modalPackets?.length)}
        packets={modalPackets || []}
        onClose={() => setModalPackets(null)}
      />
    </>
  );
}

export default TrafficTable;
