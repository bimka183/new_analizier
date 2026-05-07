import React from "react";
import UploadSection from "../components/UploadSection";
import TrafficCharts from "../components/TrafficCharts";
import TrafficPagination from "../components/TrafficPagination";
import TrafficTable from "../components/TrafficTable";
import SectionContainer from "../ui/section-container";
import { API_BASE_URL } from "../constants/trafficApp";
import { usePcapUpload } from "../hooks/usePcapUpload";
import { useTrafficDashboardView } from "../hooks/useTrafficDashboardView";
import "./AnalyzeFilePage.scss";

function AnalyzeFilePage() {
  const apiBaseRef = React.useRef(API_BASE_URL);
  const [fileRows, setFileRows] = React.useState([]);
  const {
    file,
    uploadStatus,
    analysisSummary,
    isReportAvailable,
    handleChooseFile: choosePcapFile,
    handleRemoveFile: removePcapFile,
    handleUpload: uploadPcapFile,
  } = usePcapUpload({
    apiBaseRef,
    onUploadSuccess: setFileRows,
  });

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

  const handleChooseFile = (nextFile) => {
    setFileRows([]);
    choosePcapFile(nextFile);
  };

  const handleRemoveFile = () => {
    setFileRows([]);
    removePcapFile();
  };

  const handleUpload = async () => {
    setFileRows([]);
    await uploadPcapFile();
  };

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
          threatSummary={threatSummary}
          threatRowsCount={filteredChartData.length}
          onChooseFile={handleChooseFile}
          onRemoveFile={handleRemoveFile}
          onUpload={handleUpload}
          isReportAvailable={isReportAvailable}
        />
      </SectionContainer>

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
