import React from "react";
import { useSearchParams } from "react-router-dom";
import UploadSection from "../components/UploadSection";
import TrafficCharts from "../components/TrafficCharts";
import TrafficPagination from "../components/TrafficPagination";
import TrafficTable from "../components/TrafficTable";
import SectionContainer from "../ui/section-container";
import { fetchUploadReportOverview } from "../api/uploadsApi";
import { useServerPaginatedTraffic } from "../hooks/useServerPaginatedTraffic";
import { useTrafficDashboardView } from "../hooks/useTrafficDashboardView";
import { buildThreatSummary } from "../utils/threatSummary";
import { API_BASE_URL } from "../constants/trafficApp";
import "./AnalyzeFilePage.scss";

const EMPTY_SUMMARY = {
  packets: 0,
  flows: 0,
  startTime: "—",
  duration: "—",
};

const EMPTY_THREAT_SUMMARY = [];

function AnalyzeFilePage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const uploadIdParam = searchParams.get("upload_id") ?? "";
  const isServerTableMode = Boolean(uploadIdParam);

  const [file, setFile] = React.useState(null);
  const [uploadStatus, setUploadStatus] = React.useState("idle");
  const [analysisSummary, setAnalysisSummary] = React.useState(EMPTY_SUMMARY);
  const [threatSummary, setThreatSummary] = React.useState(EMPTY_THREAT_SUMMARY);
  const [threatRowsCount, setThreatRowsCount] = React.useState(0);
  const [isReportAvailable, setIsReportAvailable] = React.useState(false);
  const [fileRows, setFileRows] = React.useState([]);
  const [overviewError, setOverviewError] = React.useState(null);

  const serverTraffic = useServerPaginatedTraffic(uploadIdParam);

  const tableSourceRows = isServerTableMode ? serverTraffic.pageRows : fileRows;

  const tableView = useTrafficDashboardView(
    tableSourceRows,
    isServerTableMode
      ? {
          tableBaseOrder: "chronological",
          serverPagination: true,
          serverTotalRows: serverTraffic.totalRows,
          itemsPerPage: serverTraffic.itemsPerPage,
          currentPage: serverTraffic.currentPage,
        }
      : { tableBaseOrder: "chronological" }
  );

  const displayThreatSummary = isServerTableMode
    ? threatSummary
    : tableView.threatSummary;

  const displayThreatRowsCount = isServerTableMode
    ? threatRowsCount
    : tableView.filteredChartData.length;

  const timersRef = React.useRef([]);

  React.useEffect(
    () => () => {
      timersRef.current.forEach((timerId) => clearTimeout(timerId));
      timersRef.current = [];
    },
    []
  );

  const clearUploadIdFromUrl = React.useCallback(() => {
    const next = new URLSearchParams(searchParams);
    if (!next.has("upload_id")) return;
    next.delete("upload_id");
    setSearchParams(next, { replace: true });
  }, [searchParams, setSearchParams]);

  const clearPendingTimers = () => {
    timersRef.current.forEach((timerId) => clearTimeout(timerId));
    timersRef.current = [];
  };

  const resetAnalysisState = React.useCallback(() => {
    setIsReportAvailable(false);
    setFileRows([]);
    setAnalysisSummary(EMPTY_SUMMARY);
    setThreatSummary(EMPTY_THREAT_SUMMARY);
    setThreatRowsCount(0);
    setOverviewError(null);
  }, []);

  React.useEffect(() => {
    if (!uploadIdParam) {
      return undefined;
    }

    let cancelled = false;

    const loadReportOverview = async () => {
      clearPendingTimers();
      setUploadStatus("processing");
      resetAnalysisState();

      try {
        const overview = await fetchUploadReportOverview(uploadIdParam);
        if (cancelled) return;

        setFile({ name: overview.upload.filename });
        setAnalysisSummary(overview.analysisSummary);
        setThreatSummary(overview.threatSummary);
        setThreatRowsCount(overview.threatRowsCount);
        setUploadStatus("completed");
        setIsReportAvailable(true);
        setOverviewError(null);
      } catch (error) {
        if (cancelled) return;
        setUploadStatus("error");
        setFile(null);
        resetAnalysisState();
        setOverviewError(error.message || "Failed to load analysis overview");
        // eslint-disable-next-line no-console
        console.error("Failed to load analysis overview", error);
      }
    };

    loadReportOverview();

    return () => {
      cancelled = true;
    };
  }, [uploadIdParam, resetAnalysisState]);

  const handleChooseFile = (nextFile) => {
    clearPendingTimers();
    clearUploadIdFromUrl();
    setFile(nextFile);
    setUploadStatus("idle");
    resetAnalysisState();
  };

  const handleRemoveFile = () => {
    clearPendingTimers();
    clearUploadIdFromUrl();
    setFile(null);
    setUploadStatus("idle");
    resetAnalysisState();
  };

  const handleUpload = async () => {
    if (!file) return;

    clearPendingTimers();
    clearUploadIdFromUrl();
    setUploadStatus("uploading");
    resetAnalysisState();

    try {
      const formData = new FormData();
      formData.append("file", file);

      const response = await fetch(`${API_BASE_URL}/api/upload`, {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`Upload failed with status ${response.status}`);
      }

      setUploadStatus("processing");
      const result = await response.json();
      const rows = result.data || [];

      const uniqueFlows = new Set(rows.map((item) => item.flow_id)).size;
      const startedAt = rows[0]?.timestamp || "—";
      const totalPackets =
        result.packets ??
        rows.reduce((acc, item) => acc + (item.packets || 0), 0);
      const flows = result.total ?? uniqueFlows;

      setFileRows(rows);
      setAnalysisSummary({
        packets: totalPackets,
        flows,
        startTime: startedAt,
        duration: "—",
      });
      setThreatSummary(buildThreatSummary(rows));
      setThreatRowsCount(rows.length);
      setUploadStatus("completed");
      setIsReportAvailable(true);
    } catch (error) {
      setUploadStatus("error");
      // eslint-disable-next-line no-console
      console.error("PCAP upload failed", error);
    }
  };

  const showCharts = !isServerTableMode && fileRows.length > 0;
  const showTable =
    isServerTableMode
      ? uploadStatus === "completed" || serverTraffic.pageRows.length > 0
      : fileRows.length > 0;
  const tableLoading = isServerTableMode && serverTraffic.loading;
  const tableError = isServerTableMode ? serverTraffic.fetchError : null;

  const paginationCurrentPage = isServerTableMode
    ? serverTraffic.currentPage
    : tableView.currentPage;
  const paginationTotalPages = isServerTableMode
    ? serverTraffic.totalPages
    : tableView.totalPages || 1;
  const paginationTotalRows = isServerTableMode
    ? serverTraffic.totalRows
    : tableView.trafficTableGroups.length;
  const paginationItemsPerPage = isServerTableMode
    ? serverTraffic.itemsPerPage
    : tableView.itemsPerPage;
  const onPaginationPrev = isServerTableMode
    ? serverTraffic.goPrev
    : () => tableView.setCurrentPage((page) => page - 1);
  const onPaginationNext = isServerTableMode
    ? serverTraffic.goNext
    : () => tableView.setCurrentPage((page) => page + 1);
  const onItemsPerPageChange = isServerTableMode
    ? serverTraffic.setItemsPerPage
    : tableView.setItemsPerPage;

  const isUploadLocked =
    uploadStatus === "uploading" ||
    uploadStatus === "processing" ||
    isServerTableMode ||
    (isReportAvailable && uploadStatus !== "error");

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
          analysisSummary={analysisSummary}
          threatSummary={displayThreatSummary}
          threatRowsCount={displayThreatRowsCount}
          onChooseFile={handleChooseFile}
          onRemoveFile={handleRemoveFile}
          onUpload={handleUpload}
          isUploadLocked={isUploadLocked}
        />
      </SectionContainer>

      {overviewError ? (
        <p className="analyze-file-page__placeholder analyze-file-page__placeholder--error" role="alert">
          {overviewError}
        </p>
      ) : null}

      {uploadStatus === "processing" && !isReportAvailable ? (
        <p className="analyze-file-page__placeholder" role="status">
          Loading analysis summary…
        </p>
      ) : null}

      {showCharts ? (
        <TrafficCharts
          trafficByIP={tableView.trafficByIP}
          anomaliesCount={tableView.anomaliesCount}
          trafficByTime={tableView.trafficByTime}
        />
      ) : null}

      {showTable ? (
        <section className="app__traffic-section" aria-labelledby="analyze-file-traffic-heading">
          <h3 id="analyze-file-traffic-heading" className="app__section-title">
            File traffic log
          </h3>
          {tableLoading ? (
            <p className="analyze-file-page__placeholder" role="status">
              Loading table page…
            </p>
          ) : null}
          {tableError ? (
            <p className="analyze-file-page__placeholder analyze-file-page__placeholder--error" role="alert">
              Failed to load traffic table.
            </p>
          ) : null}
          <div className="app__controls">
            <TrafficTable
              groups={tableView.paginatedTableGroups}
              sortColumn={tableView.sortColumn}
              sortDirection={tableView.sortDirection}
              onSortColumn={tableView.cycleTableSort}
            />
            <TrafficPagination
              currentPage={paginationCurrentPage}
              totalPages={paginationTotalPages || 1}
              totalRows={paginationTotalRows}
              itemsPerPage={paginationItemsPerPage}
              onItemsPerPageChange={onItemsPerPageChange}
              onPrev={onPaginationPrev}
              onNext={onPaginationNext}
            />
          </div>
        </section>
      ) : uploadStatus !== "processing" && !overviewError ? (
        <div className="analyze-file-page__placeholder">
          Select a file and run analysis to see file-specific tables and charts.
        </div>
      ) : null}
    </section>
  );
}

export default AnalyzeFilePage;
