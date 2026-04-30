import React, { useEffect, useState, useCallback, useRef } from "react";
import UploadSection from "./components/UploadSection";
import TrafficFilters from "./components/TrafficFilters";
import TrafficPagination from "./components/TrafficPagination";
import TrafficTable from "./components/TrafficTable";
import TrafficCharts from "./components/TrafficCharts";
import { getAnomaly } from "./utils/traffic";
import "./App.scss";

const EMPTY_ANALYSIS_SUMMARY = {
  packets: 0,
  flows: 0,
  startTime: "-",
  duration: "-",
};

const EMPTY_THREAT_SUMMARY = [
  { name: "DDoS", value: 0 },
  { name: "Port Scan", value: 0 },
  { name: "Worm Activity", value: 0 },
];

function App() {
  const [data, setData] = useState([]);
  const [totalItems, setTotalItems] = useState(0);
  const [filterIP, setFilterIP] = useState("");
  const [filterAnomaly, setFilterAnomaly] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [file, setFile] = useState(null);
  const [uploadStatus, setUploadStatus] = useState("idle");
  const [analysisSummary, setAnalysisSummary] = useState(EMPTY_ANALYSIS_SUMMARY);
  const [threatSummary, setThreatSummary] = useState(EMPTY_THREAT_SUMMARY);
  const [isReportAvailable, setIsReportAvailable] = useState(false);
  const analysisTimeoutsRef = useRef([]);

  const itemsPerPage = 20;

  const clearAnalysisTimers = useCallback(() => {
    analysisTimeoutsRef.current.forEach((timeoutId) => clearTimeout(timeoutId));
    analysisTimeoutsRef.current = [];
  }, []);

  const handleChooseFile = useCallback(
    (nextFile) => {
      setFile(nextFile);
      setUploadStatus("idle");
      setAnalysisSummary(EMPTY_ANALYSIS_SUMMARY);
      setThreatSummary(EMPTY_THREAT_SUMMARY);
      setIsReportAvailable(false);
      clearAnalysisTimers();
    },
    [clearAnalysisTimers]
  );

  const handleRemoveFile = useCallback(() => {
    handleChooseFile(null);
  }, [handleChooseFile]);

  const handleUpload = useCallback(() => {
    if (!file) return;

    clearAnalysisTimers();
    setUploadStatus("uploading");
    setIsReportAvailable(false);

    const startedAt = new Date();
    const processingTimer = window.setTimeout(() => {
      setUploadStatus("processing");
    }, 1200);

    // Hook-point for real polling/websocket updates.
    const completedTimer = window.setTimeout(() => {
      setUploadStatus("completed");
      setAnalysisSummary({
        packets: 7421,
        flows: 312,
        startTime: startedAt.toLocaleTimeString(),
        duration: "00:01:18",
      });
      setThreatSummary([
        { name: "DDoS", value: 14 },
        { name: "Port Scan", value: 9 },
        { name: "Worm Activity", value: 4 },
      ]);
      setIsReportAvailable(true);
    }, 2800);

    analysisTimeoutsRef.current = [processingTimer, completedTimer];
  }, [clearAnalysisTimers, file]);

  const fetchData = useCallback(() => {
    let url = `/api/traffic?page=${currentPage}&limit=${itemsPerPage}`;

    if (filterIP.trim() !== "") {
      url += `&source_ip=${encodeURIComponent(filterIP)}`;
    }

    fetch(url)
      .then((res) => res.json())
      .then((result) => {
        setData(result.data || []);
        setTotalItems(result.total || 0);
      });
  }, [filterIP, currentPage]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  useEffect(() => {
    return () => {
      clearAnalysisTimers();
    };
  }, [clearAnalysisTimers]);

  useEffect(() => {
    const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsHost = window.location.host || "localhost:8080";
    const ws = new WebSocket(`${wsProtocol}//${wsHost}/ws`);

    ws.onmessage = (event) => {
      const newData = JSON.parse(event.data);

      setData((prev) => {
        if (prev.find((i) => i.id === newData.id)) return prev;
        return [...prev, newData];
      });
    };

    return () => ws.close();
  }, []);

  const filteredData = data.filter((item) => {
    return (
      (filterIP === "" ||
        item.source_ip?.includes(filterIP) ||
        item.destination_ip?.includes(filterIP)) &&
      (filterAnomaly === "" || getAnomaly(item) === filterAnomaly)
    );
  });

  const totalPages = Math.ceil(totalItems / itemsPerPage);

  const paginatedData = filteredData;

  const trafficByIP = Object.values(
    filteredData.reduce((acc, cur) => {
      const ip = cur.source_ip || "unknown";

      if (!acc[ip]) {
        acc[ip] = { source_ip: ip, volume: 0 };
      }

      acc[ip].volume += cur.traffic_volume || 0;

      return acc;
    }, {})
  );

  const anomaliesCount = Object.values(
    filteredData.reduce((acc, cur) => {
      const anomaly =
        cur?.anomalies?.[0]?.anomaly_type;

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

  const trafficByTime = Object.values(
    filteredData.reduce((acc, cur) => {
      const time = (cur.timestamp || "").slice(11, 16);

      if (!time) return acc;

      if (!acc[time]) {
        acc[time] = { time, volume: 0 };
      }

      acc[time].volume += cur.traffic_volume || 0;

      return acc;
    }, {})
  );
  return (
    <div className="app">
      <h2>Network Traffic</h2>

      <UploadSection
        file={file}
        uploadStatus={uploadStatus}
        analysisSummary={analysisSummary}
        threatSummary={threatSummary}
        onChooseFile={handleChooseFile}
        onRemoveFile={handleRemoveFile}
        onUpload={handleUpload}
        isReportAvailable={isReportAvailable}
      />
      <TrafficFilters
        filterIP={filterIP}
        filterAnomaly={filterAnomaly}
        onFilterIPChange={setFilterIP}
        onFilterAnomalyChange={setFilterAnomaly}
      />
      <TrafficPagination
        currentPage={currentPage}
        totalPages={totalPages || 1}
        onPrev={() => setCurrentPage((page) => page - 1)}
        onNext={() => setCurrentPage((page) => page + 1)}
      />
      <TrafficTable data={paginatedData} />
      <TrafficCharts
        trafficByIP={trafficByIP}
        anomaliesCount={anomaliesCount}
        trafficByTime={trafficByTime}
      />
    </div>
  );
}

export default App;