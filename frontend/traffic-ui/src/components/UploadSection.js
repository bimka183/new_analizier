import React, { useMemo, useRef, useState } from "react";
import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";
import Button from "../ui/button";
import "./UploadSection.scss";

const STATUS_LABELS = {
  uploading: "Uploading",
  processing: "Processing",
  completed: "Completed",
  error: "Error",
  idle: "Idle",
};

const THREAT_COLORS = [
  "var(--button-color)",
  "var(--table-row-overload-color)",
  "var(--table-row-p2mp-color)",
  "var(--table-row-worm-color)",
  "var(--table-row-virus-color)",
  "var(--main-color)",
];

function UploadIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path
        d="M12 3l5 5h-3v6h-4V8H7l5-5zm-8 14h16v4H4v-4z"
        fill="currentColor"
      />
    </svg>
  );
}

function FileIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path
        d="M7 2h7l5 5v15H7V2zm7 1.5V8h4.5L14 3.5zM9 12h8v1.5H9V12zm0 3h8v1.5H9V15z"
        fill="currentColor"
      />
    </svg>
  );
}

function formatFileSize(sizeInBytes) {
  if (!Number.isFinite(sizeInBytes) || sizeInBytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let size = sizeInBytes;
  let unitIndex = 0;

  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024;
    unitIndex += 1;
  }

  return `${size.toFixed(size >= 10 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`;
}

function UploadSection({
  file,
  uploadStatus,
  analysisSummary,
  threatSummary,
  onChooseFile,
  onRemoveFile,
  onUpload,
  isReportAvailable,
}) {
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef(null);

  const totalThreats = useMemo(
    () => threatSummary.reduce((acc, item) => acc + item.value, 0),
    [threatSummary]
  );

  const handleDrop = (event) => {
    event.preventDefault();
    setIsDragOver(false);

    const droppedFile = event.dataTransfer.files?.[0] || null;
    onChooseFile(droppedFile);
  };

  return (
    <section className="upload-section" aria-label="Upload and analysis section">
      <div className="upload-section__row">
        <div className="upload-panel upload-panel--drop">
          <h3 className="upload-panel__title">Upload File</h3>
          <div
            className={`upload-dropzone ${isDragOver ? "upload-dropzone--active" : ""}`}
            onDragOver={(event) => {
              event.preventDefault();
              setIsDragOver(true);
            }}
            onDragLeave={() => setIsDragOver(false)}
            onDrop={handleDrop}
          >
            <UploadIcon />
            <p>Drag &amp; Drop PCAP file here</p>
            <span>or choose from your device</span>
            <input
              ref={fileInputRef}
              type="file"
              accept=".pcap,.pcapng"
              onChange={(event) => onChooseFile(event.target.files?.[0] || null)}
              className="upload-dropzone__input"
            />
            <Button onClick={() => fileInputRef.current?.click()}>Choose File</Button>
            <Button onClick={onUpload} disabled={!file || uploadStatus === "uploading"}>
              Start Analysis
            </Button>
          </div>

          {file ? (
            <div className="upload-file-meta" aria-live="polite">
              <FileIcon />
              <div className="upload-file-meta__details">
                <strong>{file.name}</strong>
                <span>{formatFileSize(file.size)}</span>
              </div>
              <button
                type="button"
                className="upload-file-meta__remove"
                onClick={onRemoveFile}
                aria-label="Remove selected file"
              >
                ×
              </button>
            </div>
          ) : null}
        </div>

        <div className="upload-panel upload-panel--summary">
          <h3 className="upload-panel__title">Analysis Summary</h3>
          <div className="analysis-summary">
            <p>
              <span>Status:</span> {STATUS_LABELS[uploadStatus] || uploadStatus}
            </p>
            <p>
              <span>Packets:</span> {analysisSummary.packets}
            </p>
            <p>
              <span>Flows:</span> {analysisSummary.flows}
            </p>
            <p>
              <span>Start Time:</span> {analysisSummary.startTime}
            </p>
            <p>
              <span>Duration:</span> {analysisSummary.duration}
            </p>
          </div>
          <Button disabled={!isReportAvailable}>View Full Report</Button>
        </div>

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
                  <strong>{item.value}</strong>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
    </section>
  );
}

export default UploadSection;
