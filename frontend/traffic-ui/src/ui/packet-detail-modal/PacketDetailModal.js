import React, { useEffect } from "react";
import Button from "../button";
import {
  getAnomaly,
  getAnomalyBadgeClassName,
  shouldShowAnomalyPill,
} from "../../utils/traffic";
import "./PacketDetailModal.scss";

function PacketDetailModal({ open, packets, onClose }) {
  useEffect(() => {
    if (!open) return undefined;

    const onKey = (e) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="packet-detail-modal"
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
        <div className="packet-detail-modal__header">
          <h3 id="packet-detail-modal-title" className="packet-detail-modal__title">
            Packets in group ({packets.length})
          </h3>
          <Button type="button" onClick={onClose}>
            Close
          </Button>
        </div>
        <div className="packet-detail-modal__body">
          <table className="packet-detail-modal__table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Anomaly</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Protocol</th>
                <th>Src Port</th>
                <th>Dst Port</th>
                <th>Volume</th>
                <th>Flags</th>
                <th>ID</th>
              </tr>
            </thead>
            <tbody>
              {packets.map((item) => {
                const anomaly = getAnomaly(item);
                return (
                  <tr key={item.id}>
                    <td>{item.timestamp}</td>
                    <td>
                      {shouldShowAnomalyPill(anomaly) ? (
                        <span
                          className={`traffic-table__anomaly-pill ${getAnomalyBadgeClassName(
                            anomaly
                          )}`}
                        >
                          {anomaly}
                        </span>
                      ) : null}
                    </td>
                    <td>{item.source_ip}</td>
                    <td>{item.destination_ip}</td>
                    <td>{item.protocol || "—"}</td>
                    <td>{item.source_port}</td>
                    <td>{item.destination_port}</td>
                    <td>{item.traffic_volume}</td>
                    <td>{item.flags}</td>
                    <td>{item.id}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export default PacketDetailModal;
