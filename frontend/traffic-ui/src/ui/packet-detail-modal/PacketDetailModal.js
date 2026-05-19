import React, { useEffect, useMemo } from "react";
import Button from "../button";
import {
  getAnomalyBadgeClassName,
  shouldShowAnomalyPill,
} from "../../utils/traffic";
import {
  getAllAnomalyLabels,
  getFlowDetailFields,
  getGroupDetailSummary,
  getModalSubtitle,
  formatTrafficField,
} from "../../utils/trafficRowDetails";
import "./PacketDetailModal.scss";

function AnomalyPills({ labels }) {
  if (!labels?.length) return <span className="packet-detail-modal__empty">—</span>;
  return (
    <div className="packet-detail-modal__anomaly-pills">
      {labels.map((label) =>
        shouldShowAnomalyPill(label) ? (
          <span
            key={label}
            className={`traffic-table__anomaly-pill ${getAnomalyBadgeClassName(label)}`}
          >
            {label}
          </span>
        ) : null
      )}
    </div>
  );
}

function GroupSummaryBlock({ summary }) {
  const metrics = [
    { label: "Flows", value: summary.flowCount },
    { label: "Total packets", value: formatTrafficField("packets", summary.totalPackets) },
    { label: "Total volume", value: formatTrafficField("traffic_volume", summary.totalVolume) },
    { label: "Flow length (sum)", value: formatTrafficField("flow_length", summary.totalFlowLength) },
    { label: "Max duration", value: formatTrafficField("duration_sec", summary.maxDurationSec) },
    { label: "BPS (sum)", value: formatTrafficField("bps", summary.totalBps) },
    { label: "Flow ID", value: summary.flowIdLabel },
    { label: "Protocol", value: summary.protocolLabel },
  ];

  return (
    <section className="packet-detail-modal__group-summary" aria-label="Group summary">
      <h4 className="packet-detail-modal__section-title">Group summary</h4>
      <dl className="packet-detail-modal__summary-grid">
        {metrics.map(({ label, value }) => (
          <div key={label} className="packet-detail-modal__summary-item">
            <dt>{label}</dt>
            <dd>{value ?? "—"}</dd>
          </div>
        ))}
      </dl>
      {summary.anomalyTypes.length > 0 ? (
        <div className="packet-detail-modal__summary-anomalies">
          <span className="packet-detail-modal__summary-anomalies-label">Anomalies</span>
          <AnomalyPills labels={summary.anomalyTypes} />
        </div>
      ) : null}
    </section>
  );
}

function FlowDetailCard({ item, index, total }) {
  const sections = useMemo(() => getFlowDetailFields(item), [item]);
  const anomalyLabels = useMemo(() => getAllAnomalyLabels(item), [item]);
  const title =
    total > 1
      ? `Flow ${index + 1} · ID ${item.id ?? "—"}`
      : "Flow parameters";

  return (
    <article className="packet-detail-modal__flow-card">
      <header className="packet-detail-modal__flow-card-header">
        <h4 className="packet-detail-modal__flow-card-title">{title}</h4>
        {total > 1 && item.flow_id ? (
          <span className="packet-detail-modal__flow-card-meta">{item.flow_id}</span>
        ) : null}
      </header>
      {sections.map((section) => (
        <section key={section.title} className="packet-detail-modal__field-section">
          <h5 className="packet-detail-modal__field-section-title">{section.title}</h5>
          {section.title === "Anomalies" ? (
            <AnomalyPills labels={anomalyLabels} />
          ) : (
            <dl className="packet-detail-modal__field-grid">
              {section.fields.map((f) => (
                <div key={f.label} className="packet-detail-modal__field-item">
                  <dt>{f.label}</dt>
                  <dd>{f.value}</dd>
                </div>
              ))}
            </dl>
          )}
        </section>
      ))}
    </article>
  );
}

function PacketDetailModal({ open, packets, onClose }) {
  useEffect(() => {
    if (!open) return undefined;

    const onKey = (e) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  const isGroup = packets?.length > 1;
  const groupSummary = useMemo(
    () => (packets?.length ? getGroupDetailSummary(packets) : null),
    [packets]
  );
  const subtitle = useMemo(() => getModalSubtitle(packets || []), [packets]);

  if (!open || !packets?.length) return null;

  const title = isGroup
    ? `Group details (${packets.length} flows)`
    : "Flow details";

  return (
    <div
      className="packet-detail-modal packet-detail-modal--open"
      role="dialog"
      aria-modal="true"
      aria-labelledby="packet-detail-modal-title"
    >
      <button
        type="button"
        className="packet-detail-modal__backdrop"
        aria-label="Close details"
        onClick={onClose}
      />
      <div className="packet-detail-modal__panel">
        <header className="packet-detail-modal__header">
          <div className="packet-detail-modal__header-text">
            <h3 id="packet-detail-modal-title" className="packet-detail-modal__title">
              {title}
            </h3>
            {subtitle ? (
              <p className="packet-detail-modal__subtitle">{subtitle}</p>
            ) : null}
          </div>
          <Button type="button" onClick={onClose}>
            Close
          </Button>
        </header>
        <div
          className="packet-detail-modal__body"
          tabIndex={0}
          aria-label="Flow details content"
        >
          {isGroup && groupSummary ? (
            <GroupSummaryBlock summary={groupSummary} />
          ) : null}
          <div className="packet-detail-modal__flow-list">
            {packets.map((item, index) => (
              <React.Fragment key={item.id ?? index}>
                {index > 0 ? (
                  <hr className="packet-detail-modal__flow-divider" aria-hidden />
                ) : null}
                <FlowDetailCard
                  item={item}
                  index={index}
                  total={packets.length}
                />
              </React.Fragment>
            ))}
          </div>
        </div>
      </div>
    </div>  
  );
}

export default PacketDetailModal;
