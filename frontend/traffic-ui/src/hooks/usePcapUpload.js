import { useCallback, useState } from "react";
import { EMPTY_ANALYSIS_SUMMARY } from "../constants/trafficApp";

export function usePcapUpload({ apiBaseRef, onUploadSuccess }) {
  const [file, setFile] = useState(null);
  const [uploadStatus, setUploadStatus] = useState("idle");
  const [analysisSummary, setAnalysisSummary] = useState(EMPTY_ANALYSIS_SUMMARY);
  const [isReportAvailable, setIsReportAvailable] = useState(false);

  const updateAnalysisSummary = useCallback((rows, total, uploadSummary, startedAt) => {
    const packetCount =
      Number(uploadSummary?.packets) ||
      rows.reduce((acc, item) => acc + (item.packets || item.length || 0), 0);
    const durationMs = startedAt ? Math.max(Date.now() - startedAt.getTime(), 0) : 0;
    const duration = new Date(durationMs).toISOString().slice(11, 19);
    const bpsAvg = Number(uploadSummary?.bps_avg) || 0;
    const avgPacketSizeAvg = Number(uploadSummary?.avg_packet_size_avg) || 0;
    const iatMsAvg = Number(uploadSummary?.iat_ms_avg) || 0;

    setAnalysisSummary({
      packets: packetCount,
      flows: Number.isFinite(total) ? total : rows.length,
      startTime: startedAt ? startedAt.toLocaleTimeString() : "-",
      duration,
      bpsAvg,
      avgPacketSizeAvg,
      iatMsAvg,
    });
    setIsReportAvailable(rows.length > 0);
  }, []);

  const handleChooseFile = useCallback((nextFile) => {
    setFile(nextFile);
    setUploadStatus("idle");
    setAnalysisSummary(EMPTY_ANALYSIS_SUMMARY);
    setIsReportAvailable(false);
  }, []);

  const handleRemoveFile = useCallback(() => {
    handleChooseFile(null);
  }, [handleChooseFile]);

  const handleUpload = useCallback(async () => {
    if (!file) return;

    setUploadStatus("uploading");
    setIsReportAvailable(false);
    const startedAt = new Date();

    try {
      const formData = new FormData();
      formData.append("file", file);

      const response = await fetch(`${apiBaseRef.current}/api/upload`, {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`Upload failed with status ${response.status}`);
      }

      setUploadStatus("processing");
      const result = await response.json();
      const uploadedRows = Array.isArray(result?.data) ? result.data : [];
      const uploadedTotal = Number(result?.total);
      const uploadSummary = result?.summary;

      onUploadSuccess?.(uploadedRows);
      updateAnalysisSummary(uploadedRows, uploadedTotal, uploadSummary, startedAt);
      setUploadStatus("completed");
    } catch (error) {
      setUploadStatus("error");
      onUploadSuccess?.([]);
      setAnalysisSummary({
        ...EMPTY_ANALYSIS_SUMMARY,
        startTime: startedAt.toLocaleTimeString(),
      });
      setIsReportAvailable(false);
      // eslint-disable-next-line no-console
      console.error("PCAP upload failed", error);
    }
  }, [apiBaseRef, file, onUploadSuccess, updateAnalysisSummary]);

  return {
    file,
    uploadStatus,
    analysisSummary,
    isReportAvailable,
    handleChooseFile,
    handleRemoveFile,
    handleUpload,
  };
}
