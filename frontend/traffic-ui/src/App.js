import React from "react";
import { Navigate, Route, Routes, useNavigate } from "react-router-dom";
import TrafficPagination from "./components/TrafficPagination";
import TrafficTable from "./components/TrafficTable";
import TrafficCharts from "./components/TrafficCharts";
import DashboardThreatPanel from "./components/DashboardThreatPanel";
import TotalFlowsCard from "./ui/total-flows-card";
import SectionContainer from "./ui/section-container";
import ThemeToggle from "./ui/theme-toggle/ThemeToggle";
import Sidebar from "./ui/sidebar/Sidebar";
import SessionsPage from "./pages/SessionsPage";
import AnalyzeFilePage from "./pages/AnalyzeFilePage";
import { useTrafficDataset } from "./hooks/useTrafficDataset";
import { useTrafficDashboardView } from "./hooks/useTrafficDashboardView";
import { getTrafficGroupSummary } from "./utils/groupTrafficRows";
import "./App.scss";

function App() {
  const navigate = useNavigate();

  const [processedFilesCount] = React.useState(0);
  const { allData, fetchWithFilters } = useTrafficDataset();

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
  } = useTrafficDashboardView(allData, { fetchFilteredFn: fetchWithFilters });
  const systemStatus = "OK";

  const handleDashboardRowClick = React.useCallback((group) => {
    const s = getTrafficGroupSummary(group.packets);

    const initialFilters = {
      source: s.sourceLabel && !s.sourceLabel.startsWith("Group") ? s.sourceLabel : "",
      destination: s.destinationLabel && s.destinationLabel !== "—" ? s.destinationLabel : "",
      protocol: s.protocolLabel && s.protocolLabel !== "—" ? s.protocolLabel : "",
      anomaly:
        s.anomalyLabel && s.anomalyLabel !== "Mixed" && s.anomalyLabel !== "None"
          ? s.anomalyLabel
          : "",
    };

    navigate("/sessions", {
      state: { initialFilters, autoDetailPackets: group.packets },
    });
  }, [navigate]);

  return (
    <div className="app-shell">
      <Sidebar
        systemStatus={systemStatus}
        processedFiles={processedFilesCount}
        flowsCount={allData.length}
      />
      <div className="app-shell__content">
        <div className="app">
          <div className="app__header">
            <h2>Network Traffic</h2>
            <ThemeToggle />
          </div>

          <Routes>
            <Route
              path="/dashboard"
              element={
                <>
                  <SectionContainer as="section" className="app__dashboard-overview">
                    <DashboardThreatPanel
                      threatSummary={threatSummary}
                      threatRowsCount={filteredChartData.length}
                    />
                  </SectionContainer>
                  <div className="app__metrics" aria-label="Dashboard metrics">
                    <TotalFlowsCard
                      trafficRows={allData}
                      trendLabel="n/a"
                      trendDirection="neutral"
                    />
                  </div>
                  <TrafficCharts
                    trafficByIP={trafficByIP}
                    anomaliesCount={anomaliesCount}
                    trafficByTime={trafficByTime}
                  />
                  <section
                    className="app__traffic-section"
                    aria-labelledby="dashboard-traffic-heading"
                  >
                    <h3 id="dashboard-traffic-heading" className="app__section-title">
                      Traffic log
                    </h3>
                    <div className="app__controls">
                      <TrafficTable
                        groups={paginatedTableGroups}
                        sortColumn={sortColumn}
                        sortDirection={sortDirection}
                        onSortColumn={cycleTableSort}
                        onRowClick={handleDashboardRowClick}
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
              }
            />
            <Route
              path="/sessions"
              element={
                <SessionsPage
                  allData={allData}
                  fetchWithFilters={fetchWithFilters}
                />
              }
            />
            <Route path="/analyze-file" element={<AnalyzeFilePage />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </div>
      </div>
    </div>
  );
}

export default App;
