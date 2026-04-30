import React, { useEffect, useState, useCallback } from "react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  LineChart, Line, ResponsiveContainer,
} from "recharts";
import "./App.scss";

function App() {
  const [data, setData] = useState([]);
  const [totalItems, setTotalItems] = useState(0);
  const [filterIP, setFilterIP] = useState("");
  const [filterAnomaly, setFilterAnomaly] = useState("");
  const [currentPage, setCurrentPage] = useState(1);
  const [file, setFile] = useState(null);

  const itemsPerPage = 20;

  // Извлекаем тип аномалии из массива anomalies
  const getAnomaly = (item) => {
    if (item?.anomalies?.length > 0) {
      return item.anomalies[0].anomaly_type;
    }
    return "None";
  };

  const getRowClassName = (anomaly) => {
    switch (anomaly) {
      case "DoS/DDoS Attack":
        return "traffic-table__row--ddos";

      case "Network Overload":
        return "traffic-table__row--overload";

      case "Network/Port Scanning":
        return "traffic-table__row--scan";

      case "Worm Activity":
        return "traffic-table__row--worm";

      case "Point-to-Multipoint":
        return "traffic-table__row--p2mp";

      case "Flow Switching":
        return "traffic-table__row--flow";

      case "Confirmed Virus Activity":
        return "traffic-table__row--virus";

      case "None":
      case "":
      case null:
      case undefined:
        return "traffic-table__row--none";

      default:
        return "traffic-table__row--default";
    }
  };

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

  // Пагинация уже пришла с бэкенда — данные уже paginated
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
  console.log("SAMPLE ITEM:", anomaliesCount.length);
  console.log(getAnomaly(data[0]));
  console.log("RAW ITEM:", data[0]);
  console.log(anomaliesCount.length)
  return (
    <div className="app">
      <h2>Network Traffic</h2>

      {/* Upload */}
      <div className="app__controls">
        <input type="file" onChange={(e) => setFile(e.target.files[0])} />
        <button onClick={handleUpload}>Upload PCAP</button>
      </div>

      {/* Filters */}
      <div className="app__controls">
        <input
          placeholder="Filter by IP"
          value={filterIP}
          onChange={(e) => setFilterIP(e.target.value)}
        />

        <select
          value={filterAnomaly}
          onChange={(e) => setFilterAnomaly(e.target.value)}
        >
          <option value="">All</option>

          <option value="DoS/DDoS Attack">DoS/DDoS</option>
          <option value="Network Overload">Overload</option>
          <option value="Network/Port Scanning">Port Scanning</option>
          <option value="Worm Activity">Worm</option>
          <option value="Confirmed Virus Activity">Virus</option>
          <option value="Point-to-Multipoint">P2MP</option>
          <option value="Flow Switching">Flow Switching</option>
        </select>
      </div>

      {/* Pagination */}
      <div className="app__pagination">
        <button disabled={currentPage === 1}
          onClick={() => setCurrentPage(p => p - 1)}>Prev</button>

        <span className="app__page-info">
          {currentPage} / {totalPages || 1}
        </span>

        <button disabled={currentPage >= totalPages}
          onClick={() => setCurrentPage(p => p + 1)}>Next</button>
      </div>

      {/* Table */}
      <table className="traffic-table">
        <thead>
          <tr>
            <th>ID</th>
            <th>Flow</th>
            <th>Time</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Src Port</th>
            <th>Dst Port</th>
            <th>Flags</th>
            <th>Volume</th>
            <th>Anomaly</th>
          </tr>
        </thead>

        <tbody>
          {paginatedData.map((item) => (
            <tr
              key={item.id}
              className={getRowClassName(getAnomaly(item))}
            >
              <td>{item.id}</td>
              <td>{item.flow_id}</td>
              <td>{item.timestamp}</td>
              <td>{item.source_ip}</td>
              <td>{item.destination_ip}</td>
              <td>{item.source_port}</td>
              <td>{item.destination_port}</td>
              <td>{item.flags}</td>
              <td>{item.traffic_volume}</td>
              <td>{getAnomaly(item)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {/* Charts */}
      <div className="app__charts">
        <div className="app__chart-card">
          <ResponsiveContainer className="app__chart">
            <BarChart data={trafficByIP}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="source_ip" />
              <YAxis tickFormatter={(v) => v.toLocaleString()} width={80} />
              <Tooltip />
              <Bar dataKey="volume" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="app__chart-card">
          <ResponsiveContainer className="app__chart">
            <BarChart data={anomaliesCount}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="anomaly_type" />
              <YAxis tickFormatter={(v) => v.toLocaleString()} width={80} />
              <Tooltip />
              <Bar dataKey="count" />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="app__chart-card">
          <ResponsiveContainer className="app__chart">
            <LineChart data={trafficByTime}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="time" />
              <YAxis tickFormatter={(v) => v.toLocaleString()} width={80} />
              <Tooltip />
              <Line type="monotone" dataKey="volume" />
            </LineChart>
          </ResponsiveContainer>
        </div>

      </div>
    </div>
  );
}

export default App;