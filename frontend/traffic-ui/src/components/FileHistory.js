import React, { useCallback, useEffect, useState } from "react";
import { fetchUploads, deleteUpload } from "../api/uploadsApi";
import Button from "../ui/button";
import "./FileHistory.scss";

function formatDate(dateStr) {
  if (!dateStr) return "-";
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return dateStr;
  return d.toLocaleString();
}

function parseSummary(raw) {
  if (!raw) return null;
  if (typeof raw === "object") return raw;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function FileHistory({ onSelectUpload, activeUploadId }) {
  const [uploads, setUploads] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchUploads();
      setUploads(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const handleSelect = useCallback(
    (id) => {
      if (activeUploadId === id) {
        onSelectUpload(null);
      } else {
        onSelectUpload(id);
      }
    },
    [activeUploadId, onSelectUpload]
  );

  const handleDelete = useCallback(
    async (e, id) => {
      e.stopPropagation();
      try {
        await deleteUpload(id);
        setUploads((prev) => prev.filter((u) => u.id !== id));
        if (activeUploadId === id) {
          onSelectUpload(null);
        }
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error("Failed to delete upload", err);
      }
    },
    [activeUploadId, onSelectUpload]
  );

  if (loading) {
    return (
      <div className="file-history">
        <h3 className="file-history__title">Analysis History</h3>
        <p className="file-history__loading">Loading history...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="file-history">
        <h3 className="file-history__title">Analysis History</h3>
        <p className="file-history__error">{error}</p>
        <Button onClick={load}>Retry</Button>
      </div>
    );
  }

  if (uploads.length === 0) {
    return (
      <div className="file-history">
        <h3 className="file-history__title">Analysis History</h3>
        <p className="file-history__empty">No previous analyses found.</p>
      </div>
    );
  }

  return (
    <div className="file-history">
      <h3 className="file-history__title">Analysis History</h3>
      <div className="file-history__list">
        {uploads.map((item) => {
          const summary = parseSummary(item.summary);
          const isActive = activeUploadId === item.id;

          return (
            <div
              key={item.id}
              className={`file-history__card${isActive ? " file-history__card--active" : ""}`}
              onClick={() => handleSelect(item.id)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => e.key === "Enter" && handleSelect(item.id)}
            >
              <div className="file-history__card-header">
                <span className="file-history__filename">{item.filename}</span>
                <button
                  type="button"
                  className="file-history__delete"
                  onClick={(e) => handleDelete(e, item.id)}
                  aria-label={`Delete ${item.filename}`}
                  title="Delete"
                >
                  ×
                </button>
              </div>
              <div className="file-history__card-meta">
                <span>{formatDate(item.uploaded_at)}</span>
                <span>{item.flow_count} flows</span>
                {summary && <span>{summary.packets ?? 0} packets</span>}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

export default FileHistory;
