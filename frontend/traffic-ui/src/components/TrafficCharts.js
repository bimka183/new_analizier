import React, { useEffect, useMemo, useState } from "react";
import {
  BarChart,
  Bar,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  LineChart,
  Line,
  ResponsiveContainer,
} from "../ui/charts";
import "./TrafficCharts.scss";

const CHART_DEFAULT_COLOR = "#255ccc";
const ANOMALY_COLOR_VAR_BY_TYPE = {
  "DoS/DDoS Attack": "--chart-bar-ddos",
  "Network Overload": "--chart-bar-overload",
  "Network/Port Scanning": "--chart-bar-scan",
  "Worm Activity": "--chart-bar-worm",
  None: "--chart-bar-none",
};

function getCssVarValue(name, fallback = CHART_DEFAULT_COLOR) {
  if (typeof window === "undefined") {
    return fallback;
  }

  const value = window
    .getComputedStyle(document.documentElement)
    .getPropertyValue(name)
    .trim();
  return value || fallback;
}

function TrafficCharts({ trafficByIP, anomaliesCount, trafficByTime }) {
  const [themeRevision, setThemeRevision] = useState(0);

  useEffect(() => {
    if (typeof window === "undefined") {
      return undefined;
    }

    const observer = new MutationObserver(() => {
      setThemeRevision((revision) => revision + 1);
    });

    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["data-theme"],
    });

    return () => observer.disconnect();
  }, []);

  const chartPalette = useMemo(
    () => ({
      grid: getCssVarValue("--chart-grid-color", "#d0d7de"),
      text: getCssVarValue("--text-color", "#0e1826"),
      line: getCssVarValue("--chart-line-color", CHART_DEFAULT_COLOR),
      volume: getCssVarValue("--chart-bar-default", CHART_DEFAULT_COLOR),
      fallback: getCssVarValue("--chart-bar-other", "#f0f0f0"),
    }),
    [themeRevision],
  );
  const tooltipContentStyle = {
    backgroundColor: "var(--chart-tooltip-background)",
    borderColor: "var(--chart-grid-color)",
    color: "var(--chart-tooltip-text-color)",
  };
  const tooltipTextStyle = { color: "var(--chart-tooltip-text-color)" };

  const chartMargin = { top: 4, right: 8, left: 0, bottom: 4 };
  const chartMarginWithLegend = { top: 4, right: 8, left: 0, bottom: 16 };
  const legendCommon = {
    wrapperStyle: { paddingTop: 4 },
    verticalAlign: "bottom",
    align: "center",
    iconType: "square",
  };

  const getAnomalyBarColor = (anomalyType) => {
    const cssVarName = ANOMALY_COLOR_VAR_BY_TYPE[anomalyType];
    if (!cssVarName) {
      return chartPalette.fallback;
    }

    return getCssVarValue(cssVarName, chartPalette.fallback);
  };

  return (
    <div className="app__charts traffic-charts">
      <div className="app__chart-card traffic-charts__card">
        <div className="traffic-charts__panel">
          <h3 className="traffic-charts__title">Traffic by source IP</h3>
          <div className="traffic-charts__plot traffic-charts__container">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={trafficByIP} margin={chartMarginWithLegend}>
                <CartesianGrid stroke={chartPalette.grid} strokeDasharray="3 3" />
                <XAxis dataKey="source_ip" stroke={chartPalette.text} />
                <YAxis
                  tickFormatter={(value) => value.toLocaleString()}
                  width={80}
                  stroke={chartPalette.text}
                />
                <Tooltip
                  contentStyle={tooltipContentStyle}
                  labelStyle={tooltipTextStyle}
                  itemStyle={tooltipTextStyle}
                  cursor={{ fill: "transparent" }}
                />
                <Legend {...legendCommon} />
                <Bar
                  name="Volume"
                  dataKey="volume"
                  fill={chartPalette.volume}
                  radius={[4, 4, 0, 0]}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="app__chart-card traffic-charts__card">
        <div className="traffic-charts__panel">
          <h3 className="traffic-charts__title">Anomalies by type</h3>
          <div className="traffic-charts__plot traffic-charts__container">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={anomaliesCount} margin={chartMargin}>
                <CartesianGrid stroke={chartPalette.grid} strokeDasharray="3 3" />
                <XAxis
                  dataKey="anomaly_type"
                  stroke={chartPalette.text}
                  interval={0}
                  angle={-18}
                  textAnchor="end"
                  height={72}
                />
                <YAxis
                  tickFormatter={(value) => value.toLocaleString()}
                  width={80}
                  stroke={chartPalette.text}
                />
                <Tooltip
                  contentStyle={tooltipContentStyle}
                  labelStyle={tooltipTextStyle}
                  itemStyle={tooltipTextStyle}
                  cursor={{ fill: "transparent" }}
                />
                <Bar dataKey="count" name="Count" radius={[4, 4, 0, 0]}>
                  {anomaliesCount.map((item, index) => (
                    <Cell
                      key={`${item.anomaly_type || "unknown"}-${index}`}
                      fill={getAnomalyBarColor(item.anomaly_type)}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
          {anomaliesCount.length > 0 ? (
            <ul
              className="traffic-charts__legend traffic-charts__legend--categories"
              aria-label="Anomaly type colors"
            >
              {anomaliesCount.map((item, index) => (
                <li key={`${item.anomaly_type || "unknown"}-legend-${index}`}>
                  <span
                    className="traffic-charts__legend-swatch"
                    style={{ backgroundColor: getAnomalyBarColor(item.anomaly_type) }}
                  />
                  <span className="traffic-charts__legend-label">{item.anomaly_type}</span>
                </li>
              ))}
            </ul>
          ) : null}
        </div>
      </div>

      <div className="app__chart-card traffic-charts__card">
        <div className="traffic-charts__panel">
          <h3 className="traffic-charts__title">Traffic over time</h3>
          <div className="traffic-charts__plot traffic-charts__container">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={trafficByTime} margin={chartMarginWithLegend}>
                <CartesianGrid stroke={chartPalette.grid} strokeDasharray="3 3" />
                <XAxis dataKey="time" stroke={chartPalette.text} />
                <YAxis
                  tickFormatter={(value) => value.toLocaleString()}
                  width={80}
                  stroke={chartPalette.text}
                />
                <Tooltip
                  contentStyle={tooltipContentStyle}
                  labelStyle={tooltipTextStyle}
                  itemStyle={tooltipTextStyle}
                  cursor={{ stroke: chartPalette.grid }}
                />
                <Legend {...legendCommon} />
                <Line
                  type="monotone"
                  name="Volume"
                  dataKey="volume"
                  stroke={chartPalette.line}
                  strokeWidth={2}
                  dot={false}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
}

export default TrafficCharts;
