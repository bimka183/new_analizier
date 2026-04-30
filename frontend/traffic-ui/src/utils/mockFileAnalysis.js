const ANOMALY_TYPES = [
  "None",
  "DoS/DDoS Attack",
  "Network Overload",
  "Network/Port Scanning",
  "Worm Activity",
  "Point-to-Multipoint",
  "Flow Switching",
  "Confirmed Virus Activity",
];

function hashString(value) {
  let hash = 0;
  for (let index = 0; index < value.length; index += 1) {
    hash = (hash << 5) - hash + value.charCodeAt(index);
    hash |= 0;
  }
  return Math.abs(hash);
}

function padToIPv4Octet(value) {
  const normalized = Number(value) || 0;
  return Math.max(1, Math.min(254, normalized));
}

function pickAnomaly(seed, index) {
  const mixed = (seed + index * 7) % 100;
  if (mixed < 52) return "None";
  return ANOMALY_TYPES[(mixed % (ANOMALY_TYPES.length - 1)) + 1];
}

function buildIP(seedA, seedB, index) {
  const a = padToIPv4Octet((seedA % 200) + 20);
  const b = padToIPv4Octet((seedB % 240) + index * 3);
  const c = padToIPv4Octet(10 + (index % 40));
  const d = padToIPv4Octet(5 + ((seedA + seedB + index) % 200));
  return `${a}.${b}.${c}.${d}`;
}

export function createMockTrafficRowsFromFile(file) {
  const fileName = String(file?.name || "uploaded.pcap");
  const fileSize = Number(file?.size) || 0;
  const baseSeed = hashString(`${fileName}:${fileSize}`);
  const now = Date.now();
  const rowsCount = 24 + (baseSeed % 24);

  return Array.from({ length: rowsCount }, (_, index) => {
    const seed = baseSeed + index * 17;
    const anomalyType = pickAnomaly(baseSeed, index);
    const timestamp = new Date(now - (rowsCount - index) * 15000).toISOString();

    return {
      id: `${baseSeed}-${index + 1}`,
      flow_id: `flow-${(seed % 18) + 1}`,
      timestamp,
      source_ip: buildIP(seed, baseSeed, index),
      destination_ip: buildIP(baseSeed, seed, index + 5),
      source_port: 1024 + (seed % 50000),
      destination_port: 20 + (seed % 8000),
      protocol: seed % 2 === 0 ? "TCP" : "UDP",
      flags: seed % 3 === 0 ? "SYN" : "ACK",
      traffic_volume: 80 + (seed % 3500),
      anomalies: anomalyType === "None" ? [] : [{ anomaly_type: anomalyType }],
    };
  });
}
