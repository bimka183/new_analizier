import { getTrafficGroupSummary } from "./groupTrafficRows";

/** @typedef {'time'|'anomaly'|'source'|'destination'|'protocol'|'srcPort'|'dstPort'|'packets'|'volume'|'flags'} TrafficTableSortColumn */

function parseTimeMs(item) {
  const t = Date.parse(item?.timestamp || "");
  return Number.isFinite(t) ? t : 0;
}

function getGroupMinTimeMs(group) {
  const packets = group?.packets;
  if (!Array.isArray(packets) || packets.length === 0) return 0;
  return Math.min(...packets.map(parseTimeMs));
}

function compareValues(a, b) {
  if (typeof a === "number" && typeof b === "number") {
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
  }
  return String(a ?? "").localeCompare(String(b ?? ""), undefined, {
    numeric: true,
    sensitivity: "base",
  });
}

/**
 * @param {TrafficTableSortColumn} columnKey
 */
function pickSortComparable(columnKey, summary, timeMs) {
  switch (columnKey) {
    case "time":
      return timeMs;
    case "anomaly":
      return summary.anomalyLabel;
    case "source":
      return summary.sourceLabel;
    case "destination":
      return summary.destinationLabel;
    case "protocol":
      return summary.protocolLabel;
    case "srcPort":
      return summary.srcPortLabel;
    case "dstPort":
      return summary.dstPortLabel;
    case "packets":
      return summary.idLabel;
    case "volume":
      return summary.volumeLabel;
    case "flags":
      return summary.flagsLabel;
    default:
      return "";
  }
}

/**
 * @param {{ packets: unknown[], key: string }[]} groups
 * @param {TrafficTableSortColumn} columnKey
 * @param {'asc'|'desc'} direction
 */
export function sortTrafficGroups(groups, columnKey, direction) {
  if (!Array.isArray(groups) || groups.length === 0) return groups;

  const mul = direction === "asc" ? 1 : -1;

  const decorated = groups.map((g) => {
    const summary = getTrafficGroupSummary(g.packets);
    const timeMs = getGroupMinTimeMs(g);
    return { group: g, summary, timeMs };
  });

  decorated.sort((a, b) => {
    const va = pickSortComparable(columnKey, a.summary, a.timeMs);
    const vb = pickSortComparable(columnKey, b.summary, b.timeMs);
    let cmp = compareValues(va, vb);
    if (cmp === 0) {
      cmp = String(a.group.key).localeCompare(String(b.group.key));
    }
    return cmp * mul;
  });

  return decorated.map((d) => d.group);
}
