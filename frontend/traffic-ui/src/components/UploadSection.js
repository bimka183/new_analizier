import React, { useMemo, useRef, useState } from "react";
import { PieChart, Pie, Cell, ResponsiveContainer } from "../ui/charts";
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
  "var(--table-row-worm-color)",
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
  threatRowsCount,
  onChooseFile,
  onRemoveFile,
  onUpload,
  isUploadLocked = false,
}) {
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef(null);

  const totalThreats = useMemo(
    () => threatSummary.reduce((acc, item) => acc + item.value, 0),
    [threatSummary]
  );

  const isAnalysisBusy =
    uploadStatus === "uploading" || uploadStatus === "processing";

  const handleDrop = (event) => {
    if (isUploadLocked) return;
    event.preventDefault();
    setIsDragOver(false);

    const droppedFile = event.dataTransfer.files?.[0] || null;
    onChooseFile(droppedFile);
  };

  const handleDragOver = (event) => {
    if (isUploadLocked) return;
    event.preventDefault();
    setIsDragOver(true);
  };

  const handleChooseFileClick = () => {
    if (isUploadLocked) return;
    fileInputRef.current?.click();
  };

  const handleFileInputChange = (event) => {
    if (isUploadLocked) return;
    onChooseFile(event.target.files?.[0] || null);
    event.target.value = "";
  };

  return (
    <section className="upload-section" aria-label="Upload and analysis section">
      <div className="upload-section__row">
        <div
          className={`upload-panel upload-panel--drop${
            isUploadLocked ? " upload-panel--drop--locked" : ""
          }`}
        >
          <h3 className="upload-panel__title">Upload File</h3>
          <div
            className={`upload-dropzone${
              isDragOver && !isUploadLocked ? " upload-dropzone--active" : ""
            }${isUploadLocked ? " upload-dropzone--locked" : ""}`}
            onDragOver={handleDragOver}
            onDragLeave={() => setIsDragOver(false)}
            onDrop={handleDrop}
            aria-disabled={isUploadLocked || undefined}
          >
            <UploadIcon />
            {isUploadLocked ? (
              <p className="upload-dropzone__locked-msg">
                {isAnalysisBusy
                  ? "Analysis in progress…"
                  : "Upload is locked while the current analysis is open."}
              </p>
            ) : (
              <>
                <p>Drag &amp; Drop PCAP file here</p>
                <span>or choose from your device</span>
              </>
            )}
            <input
              ref={fileInputRef}
              type="file"
              accept=".pcap,.pcapng"
              onChange={handleFileInputChange}
              className="upload-dropzone__input"
              disabled={isUploadLocked}
              tabIndex={isUploadLocked ? -1 : undefined}
            />
            <Button onClick={handleChooseFileClick} disabled={isUploadLocked}>
              Choose File
            </Button>
            <Button
              onClick={onUpload}
              disabled={isUploadLocked || !file || isAnalysisBusy}
            >
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
                aria-label="Clear current analysis and upload another file"
                title="Clear analysis"
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

export default UploadSection;
