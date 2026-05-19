import React, { useMemo, useState } from "react";
import PacketDetailModal from "../ui/packet-detail-modal/PacketDetailModal";
import { getTrafficGroupSummary } from "../utils/groupTrafficRows";
import {
  getAnomalyBadgeClassName,
  shouldShowAnomalyPill,
} from "../utils/traffic";
import "./TrafficTable.scss";

const TABLE_COLUMNS = [
  { key: "time", label: "Time" },
  { key: "anomaly", label: "Anomaly" },
  { key: "destination", label: "Destination" },
  { key: "source", label: "Source" },
  { key: "protocol", label: "Protocol" },
  { key: "dstPort", label: "Dst Port" },
  { key: "srcPort", label: "Src Port" },
  { key: "packets", label: "Group size" },
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

function isSamePacketSet(a, b) {
  if (!a?.length || !b?.length || a.length !== b.length) return false;
  const idsA = a.map((p) => p.id).join(",");
  const idsB = b.map((p) => p.id).join(",");
  return idsA === idsB;
}

function TrafficTable({
  groups = [],
  sortColumn = null,
  sortDirection = null,
  onSortColumn,
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

  const openDetails = (packets) => {
    setModalPackets(packets);
  };

  return (
    <>
      <table className="traffic-table">
        <thead>
          <tr>{headerCells}</tr>
        </thead>

        <tbody>
          {groups.map((group) => {
            const s = getTrafficGroupSummary(group.packets);
            const isActive = isSamePacketSet(modalPackets, group.packets);
            const rowClass = [
              "traffic-table__row--interactive",
              s.count > 1 ? "traffic-table__row--grouped" : "",
              isActive ? "traffic-table__row--active" : "",
            ]
              .filter(Boolean)
              .join(" ");
            const anomalyClass = getAnomalyBadgeClassName(s.anomalyLabel);

            return (
              <tr
                key={group.key}
                className={rowClass}
                onClick={() => openDetails(group.packets)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    openDetails(group.packets);
                  }
                }}
                tabIndex={0}
                role="button"
                aria-label="View flow details"
              >
                <td>{s.timeLabel}</td>
                <td>
                  {shouldShowAnomalyPill(s.anomalyLabel) ? (
                    <span
                      className={`traffic-table__anomaly-pill ${anomalyClass}`}
                    >
                      {s.anomalyLabel}
                    </span>
                  ) : null}
                </td>
                <td>{s.destinationLabel}</td>
                <td>{s.sourceLabel}</td>
                <td>{s.protocolLabel}</td>
                <td>{s.dstPortLabel}</td>
                <td>{s.srcPortLabel}</td>
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
