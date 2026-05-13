import { useCallback, useState } from "react";
import { EMPTY_ANALYSIS_SUMMARY } from "../constants/trafficApp";

export function usePcapUpload({ apiBaseRef, fetchAllData }) {
  const [file, setFile] = useState(null);
  const [uploadStatus, setUploadStatus] = useState("idle");
  const [analysisSummary, setAnalysisSummary] = useState(EMPTY_ANALYSIS_SUMMARY);
  const [isReportAvailable, setIsReportAvailable] = useState(false);

  const fetchAnalysisSummary = useCallback(async (startedAt) => {
    const response = await fetch(
      `${apiBaseRef.current}/api/traffic?page=1&limit=10000`
    );
    const result = await response.json();
    const rows = result.data || [];
    const packetCount = rows.reduce((acc, item) => acc + (item.length || 0), 0);
    const durationMs = startedAt ? Math.max(Date.now() - startedAt.getTime(), 0) : 0;
    const duration = new Date(durationMs).toISOString().slice(11, 19);

    setAnalysisSummary({
      packets: packetCount,
      flows: result.total || rows.length,
      startTime: startedAt ? startedAt.toLocaleTimeString() : "-",
      duration,
    });
    setIsReportAvailable(rows.length > 0);
  }, [apiBaseRef]);

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
      await fetchAllData();
      await fetchAnalysisSummary(startedAt);
      setUploadStatus("completed");
    } catch (error) {
      setUploadStatus("error");
      setAnalysisSummary({
        ...EMPTY_ANALYSIS_SUMMARY,
        startTime: startedAt.toLocaleTimeString(),
      });
      setIsReportAvailable(false);
      // eslint-disable-next-line no-console
      console.error("PCAP upload failed", error);
    }
  }, [apiBaseRef, fetchAllData, fetchAnalysisSummary, file]);

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
