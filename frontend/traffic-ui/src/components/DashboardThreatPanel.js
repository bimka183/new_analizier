import React, { useMemo } from "react";
import { Cell, Pie, PieChart, ResponsiveContainer } from "../ui/charts";
import "./UploadSection.scss";

const THREAT_COLORS = [
  "var(--button-color)",
  "var(--table-row-overload-color)",
  "var(--table-row-worm-color)",
  "var(--main-color)",
];

function DashboardThreatPanel({ threatSummary = [], threatRowsCount = 0 }) {
  const totalThreats = useMemo(
    () => threatSummary.reduce((acc, item) => acc + item.value, 0),
    [threatSummary]
  );

  return (
    <section className="upload-section" aria-label="Dashboard threat summary">
      <div className="upload-section__row">
        <div className="upload-panel upload-panel--threats">
          <h3 className="upload-panel__title">Threat Summary</h3>
          <div className="threat-summary">
            <div className="threat-summary__chart">
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie
                    data={threatSummary}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={50}
                    outerRadius={80}
                    paddingAngle={2}
                  >
                    {threatSummary.map((entry, index) => (
                      <Cell key={entry.name} fill={THREAT_COLORS[index % THREAT_COLORS.length]} />
                    ))}
                  </Pie>
                </PieChart>
              </ResponsiveContainer>
              <div className="threat-summary__total" aria-live="polite">
                {totalThreats}
              </div>
            </div>
            <ul className="threat-summary__legend">
              {threatSummary.map((item, index) => (
                <li key={item.name}>
                  <span
                    className="threat-summary__dot"
                    style={{ backgroundColor: THREAT_COLORS[index % THREAT_COLORS.length] }}
                  />
                  <span>{item.name}</span>
                  <strong>
                    {item.value}
                    {totalThreats > 0 ? ` (${Math.round((item.value / totalThreats) * 100)}%)` : ""}
                  </strong>
                </li>
              ))}
            </ul>
          </div>
          <p className="threat-summary__source">
            Based on traffic table dataset: {threatRowsCount} rows
          </p>
        </div>
      </div>
    </section>
  );
}

export default DashboardThreatPanel;
