export function aggregateTrafficBySourceIP(rows) {
  return Object.values(
    rows.reduce((acc, cur) => {
      const ip = cur.source_ip || "unknown";

      if (!acc[ip]) {
        acc[ip] = { source_ip: ip, volume: 0 };
      }

      acc[ip].volume += cur.traffic_volume || 0;

      return acc;
    }, {})
  );
}

export function aggregateAnomaliesByType(rows) {
  return Object.values(
    rows.reduce((acc, cur) => {
      const anomaly = cur?.anomalies?.[0]?.anomaly_type;

      if (!anomaly) return acc;

      if (!acc[anomaly]) {
        acc[anomaly] = {
          anomaly_type: anomaly,
          count: 0,
        };
      }

      acc[anomaly].count += 1;

      return acc;
    }, {})
  );
}

export function aggregateTrafficByTimeSlot(rows) {
  return Object.values(
    rows.reduce((acc, cur) => {
      const time = (cur.timestamp || "").slice(11, 16);

      if (!time) return acc;

      if (!acc[time]) {
        acc[time] = { time, volume: 0 };
      }

      acc[time].volume += cur.traffic_volume || 0;

      return acc;
    }, {})
  );
}
