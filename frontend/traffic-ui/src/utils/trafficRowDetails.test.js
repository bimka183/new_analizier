import {
  formatTrafficField,
  getAllAnomalyLabels,
  getGroupDetailSummary,
  getFlowDetailFields,
} from "./trafficRowDetails";

describe("formatTrafficField", () => {
  it("returns em dash for empty values", () => {
    expect(formatTrafficField("id", null)).toBe("—");
    expect(formatTrafficField("id", "")).toBe("—");
  });

  it("formats duration and iat", () => {
    expect(formatTrafficField("duration_sec", 1.5)).toContain("s");
    expect(formatTrafficField("iat_ms", 12)).toContain("ms");
  });
});

describe("getAllAnomalyLabels", () => {
  it("returns unique types from anomalies array", () => {
    const item = {
      anomalies: [
        { anomaly_type: "DoS/DDoS Attack" },
        { anomaly_type: "Network Overload" },
        { anomaly_type: "DoS/DDoS Attack" },
      ],
    };
    expect(getAllAnomalyLabels(item)).toEqual([
      "DoS/DDoS Attack",
      "Network Overload",
    ]);
  });

  it("returns empty array when no anomalies", () => {
    expect(getAllAnomalyLabels({ anomalies: [] })).toEqual([]);
  });
});

describe("getGroupDetailSummary", () => {
  it("aggregates packets and volume", () => {
    const packets = [
      { id: 1, packets: 10, traffic_volume: 100, duration_sec: 2, bps: 50, timestamp: "2024-01-01 10:00:00", source_ip: "1.1.1.1", destination_ip: "2.2.2.2", anomalies: [] },
      { id: 2, packets: 5, traffic_volume: 50, duration_sec: 5, bps: 25, timestamp: "2024-01-01 10:00:01", source_ip: "1.1.1.1", destination_ip: "2.2.2.2", anomalies: [] },
    ];
    const summary = getGroupDetailSummary(packets);
    expect(summary.totalPackets).toBe(15);
    expect(summary.totalVolume).toBe(150);
    expect(summary.maxDurationSec).toBe(5);
    expect(summary.totalBps).toBe(75);
    expect(summary.flowCount).toBe(2);
  });
});

describe("getFlowDetailFields", () => {
  it("includes identity and network sections", () => {
    const sections = getFlowDetailFields({
      id: 42,
      flow_id: "f-1",
      source_ip: "10.0.0.1",
      destination_ip: "10.0.0.2",
      protocol: "TCP",
      packets: 3,
      traffic_volume: 300,
      anomalies: [{ anomaly_type: "None" }],
    });
    expect(sections.find((s) => s.title === "Identity")).toBeTruthy();
    expect(sections.find((s) => s.title === "Network")).toBeTruthy();
  });
});
