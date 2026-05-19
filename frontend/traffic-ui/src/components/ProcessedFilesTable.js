import React, { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { fetchUploads, parseUploadSummary } from "../api/uploadsApi";
import "./ProcessedFilesTable.scss";

function formatDate(dateStr) {
  if (!dateStr) return "—";
  const d = new Date(dateStr);
  if (Number.isNaN(d.getTime())) return dateStr;
  return d.toLocaleString();
}

function ProcessedFilesTable() {
  const navigate = useNavigate();
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
      setUploads([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const handleRowActivate = useCallback(
    (uploadId) => {
      navigate(`/analyze-file?upload_id=${uploadId}`);
    },
    [navigate]
  );

  if (loading) {
    return (
      <p className="processed-files-table__status" role="status">
        Loading analyzed files…
      </p>
    );
  }

  if (error) {
    return (
      <p className="processed-files-table__status processed-files-table__status--error" role="alert">
        Failed to load analyzed files: {error}
      </p>
    );
  }

  if (uploads.length === 0) {
    return (
      <p className="processed-files-table__status">No analyzed files found.</p>
    );
  }

  return (
    <div className="processed-files-table__wrap">
      <table className="traffic-table processed-files-table">
        <thead>
          <tr>
            <th scope="col">File</th>
            <th scope="col">Uploaded</th>
            <th scope="col">Flows</th>
            <th scope="col">Packets</th>
          </tr>
        </thead>
        <tbody>
          {uploads.map((item) => {
            const summary = parseUploadSummary(item.summary);
            const packets =
              summary?.packets != null ? String(summary.packets) : "—";

            return (
              <tr
                key={item.id}
                className="processed-files-table__row"
                onClick={() => handleRowActivate(item.id)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    handleRowActivate(item.id);
                  }
                }}
                role="button"
                tabIndex={0}
                aria-label={`Open analysis for ${item.filename}`}
              >
                <td>{item.filename}</td>
                <td>{formatDate(item.uploaded_at)}</td>
                <td>{item.flow_count ?? "—"}</td>
                <td>{packets}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export default ProcessedFilesTable;
