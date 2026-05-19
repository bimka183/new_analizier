import { getAnomaly } from "./traffic";
import { getTrafficGroupSummary } from "./groupTrafficRows";

const EMPTY = "—";

function isBlank(value) {
  return value === null || value === undefined || value === "";
}

function formatNumber(value, fractionDigits) {
  const n = Number(value);
  if (!Number.isFinite(n)) return EMPTY;
  if (fractionDigits != null) {
    return n.toLocaleString(undefined, {
      maximumFractionDigits: fractionDigits,
      minimumFractionDigits: fractionDigits,
    });
  }
  return n.toLocaleString();
}

/**
 * @param {string} key
 * @param {unknown} value
 */
export function formatTrafficField(key, value) {
  if (isBlank(value)) return EMPTY;

  switch (key) {
    case "duration_sec":
      return `${formatNumber(value, 2)} s`;
    case "iat_ms":
      return `${formatNumber(value, 2)} ms`;
    case "bps":
    case "avg_packet_size":
    case "std_dev_packet_size":
      return formatNumber(value, 2);
    case "packets":
    case "length":
    case "traffic_volume":
    case "flow_length":
    case "cnt_syn":
    case "cnt_ack":
    case "cnt_fin":
    case "cnt_psh":
    case "cnt_rst":
    case "cnt_urg":
    case "upload_id":
    case "id":
      return formatNumber(value);
    default:
      return String(value);
  }
}

/**
 * Client-side enrichment for legacy rows with zero flow stats.
 * @param {Record<string, unknown>} item
 */
export function enrichFlowStatsForDisplay(item) {
  if (!item || typeof item !== "object") return {};

  const enriched = { ...item };
  let packets = Number(enriched.packets) || 0;
  let flowLength = Number(enriched.flow_length) || 0;
  const trafficVolume = Number(enriched.traffic_volume) || 0;
  const length = Number(enriched.length) || 0;
  let durationSec = Number(enriched.duration_sec) || 0;
  let bps = Number(enriched.bps) || 0;
  let avgPacketSize = Number(enriched.avg_packet_size) || 0;

  if (packets <= 0) packets = 1;
  if (flowLength <= 0) {
    if (trafficVolume > 0) flowLength = trafficVolume;
    else if (length > 0) flowLength = length;
  }
  if (avgPacketSize <= 0 && packets > 0 && flowLength > 0) {
    avgPacketSize = flowLength / packets;
  }
  if (bps <= 0 && flowLength > 0) {
    bps = durationSec > 0 ? flowLength / durationSec : flowLength;
  }

  return {
    ...enriched,
    packets,
    flow_length: flowLength,
    avg_packet_size: avgPacketSize,
    bps,
  };
}

/**
 * @param {Record<string, unknown>} item
 * @returns {string[]}
 */
export function getAllAnomalyLabels(item) {
  const fromList = (item?.anomalies || [])
    .map((a) => a?.anomaly_type)
    .filter((t) => t && t !== "None");
  const unique = [...new Set(fromList)];
  if (unique.length > 0) return unique;
  const single = getAnomaly(item);
  return single && single !== "None" ? [single] : [];
}

function field(label, key, value) {
  return { label, value: formatTrafficField(key, value) };
}

/**
 * @typedef {{ title: string, fields: { label: string, value: string }[] }} FlowDetailSection
 */

/**
 * @param {Record<string, unknown>} rawItem
 * @returns {FlowDetailSection[]}
 */
export function getFlowDetailFields(rawItem) {
  const item = enrichFlowStatsForDisplay(rawItem);
  const anomalies = getAllAnomalyLabels(item);

  const sections = [
    {
      title: "Identity",
      fields: [
        field("ID", "id", item.id),
        field("Flow ID", "flow_id", item.flow_id),
        field("Upload ID", "upload_id", item.upload_id),
      ],
    },
    {
      title: "Network",
      fields: [
        field("Interface", "interface", item.interface),
        field("IP version", "ip_version", item.ip_version),
        field("Protocol", "protocol", item.protocol),
        field("Flags", "flags", item.flags),
        field("Source IP", "source_ip", item.source_ip),
        field("Destination IP", "destination_ip", item.destination_ip),
        field("Source port", "source_port", item.source_port),
        field("Destination port", "destination_port", item.destination_port),
        
        
      ],
    },
    {
      title: "Volume",
      fields: [
        field("Length", "length", item.length),
        field("Traffic volume", "traffic_volume", item.traffic_volume),
        field("Flow length", "flow_length", item.flow_length),
        field("Packets", "packets", item.packets),
      ],
    },
    {
      title: "Timing",
      fields: [
        field("Timestamp", "timestamp", item.timestamp),
        field("Duration", "duration_sec", item.duration_sec),
        field("IAT", "iat_ms", item.iat_ms),
      ],
    },
    {
      title: "Flow stats",
      fields: [
        field("BPS", "bps", item.bps),
        field("Avg packet size", "avg_packet_size", item.avg_packet_size),
        field("Std dev packet size", "std_dev_packet_size", item.std_dev_packet_size),
      ],
    },
    {
      title: "Anomalies",
      fields: [
        {
          label: "Types",
          value: anomalies.length > 0 ? anomalies.join(", ") : EMPTY,
        },
      ],
    },
  ];

  return sections;
}

function sumField(packets, key) {
  return packets.reduce((acc, p) => acc + (Number(p[key]) || 0), 0);
}

function maxField(packets, key) {
  if (packets.length === 0) return 0;
  return Math.max(...packets.map((p) => Number(p[key]) || 0));
}

function allEqualField(packets, key) {
  if (packets.length === 0) return true;
  const first = packets[0][key];
  return packets.every((p) => p[key] === first);
}

/**
 * @param {Record<string, unknown>[]} packets
 */
export function getGroupDetailSummary(packets) {
  const tableSummary = getTrafficGroupSummary(packets);
  const enriched = packets.map(enrichFlowStatsForDisplay);

  const anomalySet = new Set();
  packets.forEach((p) => {
    getAllAnomalyLabels(p).forEach((a) => anomalySet.add(a));
  });

  const flowIdLabel = allEqualField(packets, "flow_id")
    ? packets[0]?.flow_id || EMPTY
    : "Various";

  return {
    flowCount: packets.length,
    timeLabel: tableSummary.timeLabel,
    sourceLabel: tableSummary.sourceLabel,
    destinationLabel: tableSummary.destinationLabel,
    anomalyLabel: tableSummary.anomalyLabel,
    protocolLabel: tableSummary.protocolLabel,
    flowIdLabel,
    totalPackets: sumField(enriched, "packets"),
    totalVolume: sumField(enriched, "traffic_volume"),
    totalFlowLength: sumField(enriched, "flow_length"),
    maxDurationSec: maxField(enriched, "duration_sec"),
    totalBps: sumField(enriched, "bps"),
    anomalyTypes: [...anomalySet],
  };
}

/**
 * @param {Record<string, unknown>[]} packets
 */
export function getModalSubtitle(packets) {
  if (!packets?.length) return "";
  const summary = getGroupDetailSummary(packets);
  const route = `${summary.destinationLabel} → ${summary.sourceLabel}`;
  return `${summary.timeLabel} · ${route}`;
}
