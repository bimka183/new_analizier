import React from "react";
import UploadSection from "../components/UploadSection";
import FileHistory from "../components/FileHistory";
import TrafficPagination from "../components/TrafficPagination";
import TrafficTable from "../components/TrafficTable";
import SectionContainer from "../ui/section-container";
import { API_BASE_URL, KNOWN_THREAT_TYPES } from "../constants/trafficApp";
import { usePcapUpload } from "../hooks/usePcapUpload";
import { useServerPaginatedTraffic } from "../hooks/useServerPaginatedTraffic";
import { fetchUploadById } from "../api/uploadsApi";
import { groupTrafficRows } from "../utils/groupTrafficRows";
import "./AnalyzeFilePage.scss";

const EMPTY_THREAT_SUMMARY = KNOWN_THREAT_TYPES.map((name) => ({ name, value: 0 }));

function parseSummaryField(raw) {
  if (!raw) return null;
  if (typeof raw === "object") return raw;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function AnalyzeFilePage() {
  const apiBaseRef = React.useRef(API_BASE_URL);
  const [activeUploadId, setActiveUploadId] = React.useState(null);
  const [historyKey, setHistoryKey] = React.useState(0);
  const [threatSummary, setThreatSummary] = React.useState(EMPTY_THREAT_SUMMARY);

  const {
    pageRows,
    totalRows,
    totalPages,
    currentPage,
    setCurrentPage,
    itemsPerPage,
    setItemsPerPage,
    loading: tableLoading,
    goNext,
    goPrev,
  } = useServerPaginatedTraffic(activeUploadId);

  const {
    file,
    uploadStatus,
    uploadProgress,
    processingProgress,
    processingPhase,
    analysisSummary,
    isReportAvailable,
    handleChooseFile: choosePcapFile,
    handleRemoveFile: removePcapFile,
    handleUpload: uploadPcapFile,
  } = usePcapUpload({
    apiBaseRef,
    onUploadComplete: (uploadId, summary) => {
      if (uploadId) {
        setActiveUploadId(uploadId);
        setHistoryKey((k) => k + 1);
        applyThreatSummary(summary);
      } else {
        setActiveUploadId(null);
        setThreatSummary(EMPTY_THREAT_SUMMARY);
      }
    },
  });

  const applyThreatSummary = React.useCallback((summary) => {
    const ts = summary?.threat_summary;
    if (Array.isArray(ts) && ts.length > 0) {
      setThreatSummary(ts);
    } else {
      setThreatSummary(EMPTY_THREAT_SUMMARY);
    }
  }, []);

  const handleChooseFile = (nextFile) => {
    setActiveUploadId(null);
    setThreatSummary(EMPTY_THREAT_SUMMARY);
    choosePcapFile(nextFile);
  };

  const handleRemoveFile = () => {
    setActiveUploadId(null);
    setThreatSummary(EMPTY_THREAT_SUMMARY);
    removePcapFile();
  };

  const handleUpload = async () => {
    setActiveUploadId(null);
    setThreatSummary(EMPTY_THREAT_SUMMARY);
    await uploadPcapFile();
  };

  const handleSelectFromHistory = React.useCallback(
    async (uploadId) => {
      if (uploadId) {
        setActiveUploadId(uploadId);
        try {
          const upload = await fetchUploadById(uploadId);
          const summary = parseSummaryField(upload.summary);
          applyThreatSummary(summary);
        } catch {
          setThreatSummary(EMPTY_THREAT_SUMMARY);
        }
      } else {
        setActiveUploadId(null);
        setThreatSummary(EMPTY_THREAT_SUMMARY);
      }
    },
    [applyThreatSummary]
  );

  const tableGroups = React.useMemo(() => groupTrafficRows(pageRows), [pageRows]);

  const hasData = activeUploadId && totalRows > 0;

  return (
    <section className="analyze-file-page">
      <h2>Analyze file</h2>
      <p className="analyze-file-page__lead">
        Upload one PCAP file and inspect a dedicated analysis view (tables/charts are isolated per
        selected file).
      </p>

      <SectionContainer as="section" className="analyze-file-page__upload-shell">
        <UploadSection
          file={file}
          uploadStatus={uploadStatus}
          uploadProgress={uploadProgress}
          processingProgress={processingProgress}
          processingPhase={processingPhase}
          analysisSummary={analysisSummary}
          threatSummary={threatSummary}
          threatRowsCount={totalRows}
          onChooseFile={handleChooseFile}
          onRemoveFile={handleRemoveFile}
          onUpload={handleUpload}
          isReportAvailable={isReportAvailable}
        />
      </SectionContainer>

      <SectionContainer className="analyze-file-page__history-shell">
        <FileHistory
          key={historyKey}
          onSelectUpload={handleSelectFromHistory}
          activeUploadId={activeUploadId}
        />
      </SectionContainer>

      {hasData ? (
        <>
          <section className="app__traffic-section" aria-labelledby="analyze-file-traffic-heading">
            <h3 id="analyze-file-traffic-heading" className="app__section-title">
              Traffic log ({totalRows.toLocaleString()} flows)
            </h3>
            <div className="app__controls">
              <TrafficTable groups={tableGroups} enableDetailsForSingleRow />
              <TrafficPagination
                currentPage={currentPage}
                totalPages={totalPages}
                totalRows={totalRows}
                itemsPerPage={itemsPerPage}
                onItemsPerPageChange={setItemsPerPage}
                onPrev={goPrev}
                onNext={goNext}
              />
            </div>
          </section>
        </>
      ) : activeUploadId && tableLoading ? (
        <div className="analyze-file-page__placeholder">Loading traffic data...</div>
      ) : (
        <div className="analyze-file-page__placeholder">
          Select a file and run analysis, or pick a previous result from history.
        </div>
      )}
    </section>
  );
}

export default AnalyzeFilePage;
