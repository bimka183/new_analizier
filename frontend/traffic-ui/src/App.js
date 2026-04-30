import React, { useEffect, useState, useCallback } from "react";
import UploadControls from "./components/UploadControls";
import TrafficFilters from "./components/TrafficFilters";
import TrafficPagination from "./components/TrafficPagination";
import TrafficTable from "./components/TrafficTable";
import TrafficCharts from "./components/TrafficCharts";
import { getAnomaly } from "./utils/traffic";
import "./App.scss";

function App() {
  const [data, setData] = useState([]);
  const [totalItems, setTotalItems] = useState(0);
  const [filterIP, setFilterIP] = useState("");
  const [filterAnomaly, setFilterAnomaly] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [file, setFile] = useState(null);

  const itemsPerPage = 20;

  const handleUpload = async () => {
    if (!file) return;

    const formData = new FormData();
    formData.append("file", file);

    await fetch("/api/upload", {
      method: "POST",
      body: formData,
    });

    fetchData();
  };

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

      <UploadControls setFile={setFile} onUpload={handleUpload} />
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