import React from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  LineChart,
  Line,
  ResponsiveContainer,
} from "recharts";

function TrafficCharts({ trafficByIP, anomaliesCount, trafficByTime }) {
  return (
    <div className="app__charts">
      <div className="app__chart-card">
        <ResponsiveContainer className="app__chart">
          <BarChart data={trafficByIP}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="source_ip" />
            <YAxis tickFormatter={(value) => value.toLocaleString()} width={80} />
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
            <YAxis tickFormatter={(value) => value.toLocaleString()} width={80} />
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
            <YAxis tickFormatter={(value) => value.toLocaleString()} width={80} />
            <Tooltip />
            <Line type="monotone" dataKey="volume" />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

export default TrafficCharts;
