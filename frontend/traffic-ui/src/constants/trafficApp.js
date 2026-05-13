const resolveDefaultApiBaseUrl = () => {
  if (typeof window === "undefined") {
    return "http://localhost:8080";
  }

  const { protocol, hostname } = window.location;
  const normalizedProtocol = protocol === "https:" ? "https" : "http";
  return `${normalizedProtocol}://${hostname}:8080`;
};

export const API_BASE_URL =
  process.env.REACT_APP_API_BASE_URL || resolveDefaultApiBaseUrl();

export const EMPTY_ANALYSIS_SUMMARY = {
  packets: 0,
  flows: 0,
  startTime: "-",
  duration: "-",
  bpsAvg: 0,
  avgPacketSizeAvg: 0,
  iatMsAvg: 0,
};

export const KNOWN_THREAT_TYPES = [
  "DoS/DDoS Attack",
  "Network Overload",
  "Network/Port Scanning",
  "Worm Activity",
  "Confirmed Virus Activity",
  "Point-to-Multipoint",
  "Flow Switching",
];

/** Default rows per page (initial state); user can switch via `PAGE_SIZE_OPTIONS`. */
export const ITEMS_PER_PAGE = 10;

export const PAGE_SIZE_OPTIONS = [5, 10, 15];
