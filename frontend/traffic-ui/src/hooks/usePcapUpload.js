import { useCallback, useRef, useState } from "react";
import { EMPTY_ANALYSIS_SUMMARY, API_BASE_URL } from "../constants/trafficApp";
import { fetchUploadById } from "../api/uploadsApi";

export function usePcapUpload({ apiBaseRef, onUploadComplete }) {
  const [file, setFile] = useState(null);
  const [uploadStatus, setUploadStatus] = useState("idle");
  const [uploadProgress, setUploadProgress] = useState(0);
  const [processingProgress, setProcessingProgress] = useState(0);
  const [processingPhase, setProcessingPhase] = useState("");
  const [analysisSummary, setAnalysisSummary] = useState(EMPTY_ANALYSIS_SUMMARY);
  const [isReportAvailable, setIsReportAvailable] = useState(false);

  const abortRef = useRef(null);
  const sseRef = useRef(null);

  const cleanup = useCallback(() => {
    if (sseRef.current) {
      sseRef.current.close();
      sseRef.current = null;
    }
  }, []);

  const updateAnalysisSummaryFromUpload = useCallback((summary, flowCount, startedAt) => {
    const durationMs = startedAt ? Math.max(Date.now() - startedAt.getTime(), 0) : 0;
    const duration = new Date(durationMs).toISOString().slice(11, 19);

    setAnalysisSummary({
      packets: Number(summary?.packets) || 0,
      flows: flowCount || Number(summary?.flows) || 0,
      startTime: startedAt ? startedAt.toLocaleTimeString() : "-",
      duration,
      bpsAvg: Number(summary?.bps_avg) || 0,
      avgPacketSizeAvg: Number(summary?.avg_packet_size_avg) || 0,
      iatMsAvg: Number(summary?.iat_ms_avg) || 0,
    });
    setIsReportAvailable(flowCount > 0);
  }, []);

  const subscribeToProgress = useCallback(
    (uploadId, startedAt) => {
      const base = apiBaseRef.current || API_BASE_URL;
      const es = new EventSource(`${base}/api/uploads/${uploadId}/progress`);
      sseRef.current = es;

      es.onmessage = async (event) => {
        try {
          const data = JSON.parse(event.data);
          setProcessingPhase(data.phase || "");
          setProcessingProgress(data.progress || 0);

          if (data.phase === "done") {
            es.close();
            sseRef.current = null;

            const upload = await fetchUploadById(uploadId);
            const summary =
              typeof upload.summary === "string" ? JSON.parse(upload.summary) : upload.summary;

            updateAnalysisSummaryFromUpload(summary, upload.flow_count, startedAt);
            onUploadComplete?.(uploadId, summary);
            setUploadStatus("completed");
          } else if (data.phase === "error") {
            es.close();
            sseRef.current = null;
            setUploadStatus("error");
            onUploadComplete?.(null, null);
          }
        } catch {
          // ignore parse errors
        }
      };

      es.onerror = () => {
        es.close();
        sseRef.current = null;
      };
    },
    [apiBaseRef, onUploadComplete, updateAnalysisSummaryFromUpload]
  );

  const handleChooseFile = useCallback(
    (nextFile) => {
      cleanup();
      setFile(nextFile);
      setUploadStatus("idle");
      setUploadProgress(0);
      setProcessingProgress(0);
      setProcessingPhase("");
      setAnalysisSummary(EMPTY_ANALYSIS_SUMMARY);
      setIsReportAvailable(false);
    },
    [cleanup]
  );

  const handleRemoveFile = useCallback(() => {
    handleChooseFile(null);
  }, [handleChooseFile]);

  const handleUpload = useCallback(() => {
    if (!file) return;

    cleanup();
    setUploadStatus("uploading");
    setUploadProgress(0);
    setProcessingProgress(0);
    setProcessingPhase("");
    setIsReportAvailable(false);
    const startedAt = new Date();

    const formData = new FormData();
    formData.append("file", file);

    const xhr = new XMLHttpRequest();
    abortRef.current = xhr;

    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) {
        const pct = Math.round((event.loaded / event.total) * 100);
        setUploadProgress(pct);
      }
    };

    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          const result = JSON.parse(xhr.responseText);
          const uploadId = result.upload_id;
          if (uploadId) {
            setUploadStatus("processing");
            setUploadProgress(100);
            subscribeToProgress(uploadId, startedAt);
          } else {
            setUploadStatus("error");
            onUploadComplete?.(null, null);
          }
        } catch {
          setUploadStatus("error");
          onUploadComplete?.(null, null);
        }
      } else {
        setUploadStatus("error");
        onUploadComplete?.(null, null);
      }
    };

    xhr.onerror = () => {
      setUploadStatus("error");
      onUploadComplete?.(null, null);
      setAnalysisSummary({
        ...EMPTY_ANALYSIS_SUMMARY,
        startTime: startedAt.toLocaleTimeString(),
      });
      setIsReportAvailable(false);
    };

    const base = apiBaseRef.current || API_BASE_URL;
    xhr.open("POST", `${base}/api/upload`);
    xhr.send(formData);
  }, [apiBaseRef, file, onUploadComplete, cleanup, subscribeToProgress]);

  return {
    file,
    uploadStatus,
    uploadProgress,
    processingProgress,
    processingPhase,
    analysisSummary,
    isReportAvailable,
    handleChooseFile,
    handleRemoveFile,
    handleUpload,
  };
}
