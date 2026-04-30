import { KNOWN_THREAT_TYPES } from "../constants/trafficApp";
import { getAnomaly } from "./traffic";

export function buildThreatSummary(records) {
  const anomalyCountMap = records.reduce((acc, item) => {
    const anomaly = getAnomaly(item);
    if (anomaly === "None") return acc;
    acc[anomaly] = (acc[anomaly] || 0) + 1;
    return acc;
  }, {});

  const knownThreats = KNOWN_THREAT_TYPES.map((name) => ({
    name,
    value: anomalyCountMap[name] || 0,
  }));

  const extraThreats = Object.entries(anomalyCountMap)
    .filter(([name]) => !KNOWN_THREAT_TYPES.includes(name))
    .sort(([, leftCount], [, rightCount]) => rightCount - leftCount)
    .map(([name, value]) => ({ name, value }));

  return [...knownThreats, ...extraThreats];
}
