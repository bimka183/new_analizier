import React, { useId, useMemo } from "react";
import { Area, AreaChart, ResponsiveContainer } from "../charts";
import "./TotalFlowsCard.scss";

function toSparklineData(rows = []) {
  if (!Array.isArray(rows) || rows.length === 0) {
    return [];
  }

  const buckets = rows.reduce((acc, item) => {
    const timeKey = String(item?.timestamp || "").slice(11, 16);
    if (!timeKey) {
      return acc;
    }

    if (!acc[timeKey]) {
      acc[timeKey] = { time: timeKey, value: 0 };
    }

    acc[timeKey].value += 1;
    return acc;
  }, {});

  return Object.values(buckets);
}

function formatFlows(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return "0";
  }
  return numeric.toLocaleString();
}

function TotalFlowsCard({
  title = "Total Flows",
  totalValue,
  trendLabel = "n/a",
  trendDirection = "neutral",
  trendContext = "vs last analysis",
  sparklineData = [],
  trafficRows = null,
  className = "",
}) {
  const gradientId = useId();
  const total = useMemo(() => {
    if (Number.isFinite(Number(totalValue))) {
      return Number(totalValue);
    }

    if (Array.isArray(trafficRows)) {
      return trafficRows.length;
    }

    return 0;
  }, [totalValue, trafficRows]);

  const chartData = useMemo(() => {
    if (Array.isArray(sparklineData) && sparklineData.length > 0) {
      return sparklineData;
    }

    if (Array.isArray(trafficRows) && trafficRows.length > 0) {
      return toSparklineData(trafficRows);
    }

    return [];
  }, [sparklineData, trafficRows]);

  const trendIcon =
    trendDirection === "down" ? "↓" : trendDirection === "up" ? "↑" : "→";
  const rootClassName = ["total-flows-card", className].filter(Boolean).join(" ");

  return (
    <section className={rootClassName} aria-label="Total flows summary">
      <header className="total-flows-card__header">
        <p className="total-flows-card__title">{title}</p>
        <span className="total-flows-card__icon" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none">
            <circle cx="12" cy="12" r="9" />
            <path d="M3 12H21" />
            <path d="M12 3C9 6 9 18 12 21" />
            <path d="M12 3C15 6 15 18 12 21" />
          </svg>
        </span>
      </header>

      <div className="total-flows-card__value" aria-live="polite">
        {formatFlows(total)}
      </div>

      <footer className="total-flows-card__footer">
        <div className="total-flows-card__trend">
          <span className="total-flows-card__trend-value">
            <span aria-hidden="true">{trendIcon}</span> {trendLabel}
          </span>
          <span className="total-flows-card__trend-context">{trendContext}</span>
        </div>

        <div className="total-flows-card__sparkline" aria-hidden="true">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData}>
              <defs>
                <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--main-color)" stopOpacity={0.45} />
                  <stop offset="100%" stopColor="var(--main-color)" stopOpacity={0} />
                </linearGradient>
              </defs>
              <Area
                type="monotone"
                dataKey="value"
                stroke="var(--main-color)"
                strokeWidth={2}
                fill={`url(#${gradientId})`}
                dot={false}
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </footer>
    </section>
  );
}

export default TotalFlowsCard;
