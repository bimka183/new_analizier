export const getAnomaly = (item) => {
  if (item?.anomalies?.length > 0) {
    return item.anomalies[0].anomaly_type;
  }

  return "None";
};

export const getRowClassName = (anomaly) => {
  switch (anomaly) {
    case "DoS/DDoS Attack":
      return "traffic-table__row--ddos";
    case "Network Overload":
      return "traffic-table__row--overload";
    case "Network/Port Scanning":
      return "traffic-table__row--scan";
    case "Worm Activity":
      return "traffic-table__row--worm";
    case "None":
    case "":
    case null:
    case undefined:
      return "traffic-table__row--none";
    default:
      return "traffic-table__row--default";
  }
};

export const getAnomalyBadgeClassName = (anomaly) => {
  const rowClass = getRowClassName(anomaly);
  return rowClass.replace("__row--", "__anomaly--");
};

export const shouldShowAnomalyPill = (anomaly) =>
  getRowClassName(anomaly) !== "traffic-table__row--none";
