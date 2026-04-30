import { getAnomaly } from "./traffic";

/** @typedef {{ id: number|string }} TrafficItem */

export const DDOS_ANOMALY_TYPE = "DoS/DDoS Attack";

/**
 * Packets from the same source within this window are merged into one row.
 * Different sources are merged only when all packets in the burst are DDoS-classified.
 */
export const DEFAULT_GROUP_TIME_WINDOW_MS = 1000;

function parseTimeMs(item) {
  const t = Date.parse(item?.timestamp || "");
  return Number.isFinite(t) ? t : 0;
}

function allEqualBy(items, getter) {
  if (items.length === 0) return true;
  const first = getter(items[0]);
  return items.every((p) => getter(p) === first);
}

function allSameAnomalyType(items) {
  if (items.length === 0) return true;
  const a0 = getAnomaly(items[0]);
  return items.every((p) => getAnomaly(p) === a0);
}

/**
 * @param {TrafficItem[]} items
 * @param {{ timeWindowMs?: number }} [options]
 * @returns {{ packets: TrafficItem[], key: string }[]}
 */
export function groupTrafficRows(items, options = {}) {
  const timeWindowMs =
    options.timeWindowMs ?? DEFAULT_GROUP_TIME_WINDOW_MS;

  if (!Array.isArray(items) || items.length === 0) return [];

  const sorted = [...items].sort(
    (a, b) => parseTimeMs(a) - parseTimeMs(b)
  );
  /** @type {TrafficItem[][]} */
  const chunks = [];
  /** @type {TrafficItem[]} */
  let current = [];

  const flush = () => {
    if (current.length) {
      chunks.push(current);
      current = [];
    }
  };

  for (const p of sorted) {
    if (current.length === 0) {
      current.push(p);
      continue;
    }

    const first = current[0];
    const t0 = parseTimeMs(first);
    const tp = parseTimeMs(p);

    if (tp - t0 > timeWindowMs) {
      flush();
      current.push(p);
      continue;
    }

    if (p.source_ip === first.source_ip) {
      current.push(p);
      continue;
    }

    const pIsDdos = getAnomaly(p) === DDOS_ANOMALY_TYPE;
    const groupAllDdos = current.every(
      (x) => getAnomaly(x) === DDOS_ANOMALY_TYPE
    );

    if (pIsDdos && groupAllDdos) {
      current.push(p);
      continue;
    }

    flush();
    current.push(p);
  }

  flush();

  return chunks.map((packets) => ({
    packets,
    key: `grp-${packets[0]?.id}-${packets.length}-${parseTimeMs(packets[0])}`,
  }));
}

/**
 * @param {TrafficItem[]} packets
 */
export function getTrafficGroupSummary(packets) {
  const n = packets.length;
  const first = packets[0];
  const sorted = [...packets].sort(
    (a, b) => parseTimeMs(a) - parseTimeMs(b)
  );
  const tMin = sorted[0]?.timestamp ?? "";
  const tMax = sorted[sorted.length - 1]?.timestamp ?? "";

  const uniqueSources = new Set(
    packets.map((p) => p.source_ip).filter(Boolean)
  );
  const multiIpDdosBurst =
    uniqueSources.size > 1 &&
    packets.every((p) => getAnomaly(p) === DDOS_ANOMALY_TYPE);

  const sameAnomaly = allSameAnomalyType(packets);
  const anomalyLabel = sameAnomaly
    ? getAnomaly(first)
    : "Mixed";

  const volumeSum = packets.reduce(
    (acc, p) => acc + (Number(p.traffic_volume) || 0),
    0
  );

  return {
    count: n,
    idLabel: n,
    timeLabel: tMin === tMax ? tMin : `${tMin} – ${tMax}`,
    protocolLabel: allEqualBy(packets, (x) => x.protocol)
      ? first.protocol || "—"
      : "—",
    sourceLabel: multiIpDdosBurst
      ? `Group (${uniqueSources.size} IPs)`
      : first.source_ip,
    destinationLabel: allEqualBy(
      packets,
      (x) => x.destination_ip
    )
      ? first.destination_ip
      : "—",
    srcPortLabel: allEqualBy(packets, (x) => x.source_port)
      ? first.source_port
      : "—",
    dstPortLabel: allEqualBy(packets, (x) => x.destination_port)
      ? first.destination_port
      : "—",
    flagsLabel: allEqualBy(packets, (x) => x.flags)
      ? first.flags
      : "—",
    volumeLabel: volumeSum,
    anomalyLabel,
    sameAnomaly,
  };
}
