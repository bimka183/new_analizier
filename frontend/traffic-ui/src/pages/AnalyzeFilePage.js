import React from "react";
import UploadSection from "../components/UploadSection";
import TrafficCharts from "../components/TrafficCharts";
import TrafficPagination from "../components/TrafficPagination";
import TrafficTable from "../components/TrafficTable";
import { useTrafficDashboardView } from "../hooks/useTrafficDashboardView";
import { createMockTrafficRowsFromFile } from "../utils/mockFileAnalysis";
import "./AnalyzeFilePage.scss";

const EMPTY_SUMMARY = {
  packets: 0,
  flows: 0,
  startTime: "—",
  duration: "—",
};

function AnalyzeFilePage() {
  const [file, setFile] = React.useState(null);
  const [uploadStatus, setUploadStatus] = React.useState("idle");
  const [analysisSummary, setAnalysisSummary] = React.useState(EMPTY_SUMMARY);
  const [isReportAvailable, setIsReportAvailable] = React.useState(false);
  const [fileRows, setFileRows] = React.useState([]);

  const {
    sortColumn,
    sortDirection,
    cycleTableSort,
    itemsPerPage,
    setItemsPerPage,
    currentPage,
    setCurrentPage,
    filteredChartData,
    totalPages,
    trafficTableGroups,
    paginatedTableGroups,
    trafficByIP,
    anomaliesCount,
    trafficByTime,
    threatSummary,
  } = useTrafficDashboardView(fileRows, { tableBaseOrder: "chronological" });

  const timersRef = React.useRef([]);

  React.useEffect(
    () => () => {
      timersRef.current.forEach((timerId) => clearTimeout(timerId));
      timersRef.current = [];
    },
    []
  );

  const clearPendingTimers = () => {
    timersRef.current.forEach((timerId) => clearTimeout(timerId));
    timersRef.current = [];
  };

  const handleChooseFile = (nextFile) => {
    clearPendingTimers();
    setFile(nextFile);
    setUploadStatus("idle");
    setIsReportAvailable(false);
    setFileRows([]);
    setAnalysisSummary(EMPTY_SUMMARY);
  };

  const handleRemoveFile = () => {
    clearPendingTimers();
    setFile(null);
    setUploadStatus("idle");
    setIsReportAvailable(false);
    setFileRows([]);
    setAnalysisSummary(EMPTY_SUMMARY);
  };

  const handleUpload = () => {
    if (!file) return;

    clearPendingTimers();
    setUploadStatus("uploading");
    setIsReportAvailable(false);
    setFileRows([]);
    setAnalysisSummary(EMPTY_SUMMARY);

    const mockRows = createMockTrafficRowsFromFile(file);
    const uniqueFlows = new Set(mockRows.map((item) => item.flow_id)).size;
    const startedAt = mockRows[0]?.timestamp || "—";

    const processingTimer = setTimeout(() => {
      setUploadStatus("processing");
    }, 450);

    const completionTimer = setTimeout(() => {
      setFileRows(mockRows);
      setAnalysisSummary({
        packets: mockRows.length,
        flows: uniqueFlows,
        startTime: startedAt,
        duration: `${Math.max(1, Math.ceil(mockRows.length / 5))} min`,
      });
      setUploadStatus("completed");
      setIsReportAvailable(true);
    }, 1200);

    timersRef.current = [processingTimer, completionTimer];
  };

  return (
    <section className="analyze-file-page">
      <h2>Analyze file</h2>
      <p className="analyze-file-page__lead">
        Upload one PCAP file and inspect a dedicated analysis view (tables/charts are isolated per
        selected file).
      </p>

      <UploadSection
        file={file}
        uploadStatus={uploadStatus}
        analysisSummary={analysisSummary}
        threatSummary={threatSummary}
        threatRowsCount={filteredChartData.length}
        onChooseFile={handleChooseFile}
        onRemoveFile={handleRemoveFile}
        onUpload={handleUpload}
        isReportAvailable={isReportAvailable}
      />

      {fileRows.length > 0 ? (
        <>
          <TrafficCharts
            trafficByIP={trafficByIP}
            anomaliesCount={anomaliesCount}
            trafficByTime={trafficByTime}
          />
          <section className="app__traffic-section" aria-labelledby="analyze-file-traffic-heading">
            <h3 id="analyze-file-traffic-heading" className="app__section-title">
              File traffic log
            </h3>
            <div className="app__controls">
              <TrafficTable
                groups={paginatedTableGroups}
                sortColumn={sortColumn}
                sortDirection={sortDirection}
                onSortColumn={cycleTableSort}
              />
              <TrafficPagination
                currentPage={currentPage}
                totalPages={totalPages || 1}
                totalRows={trafficTableGroups.length}
                itemsPerPage={itemsPerPage}
                onItemsPerPageChange={setItemsPerPage}
                onPrev={() => setCurrentPage((page) => page - 1)}
                onNext={() => setCurrentPage((page) => page + 1)}
              />
            </div>
          </section>
        </>
      ) : (
        <div className="analyze-file-page__placeholder">
          Select a file and run analysis to see file-specific tables and charts.
        </div>
      )}
    </section>
  );
}

export default AnalyzeFilePage;
