import React from "react";
import { Navigate, Route, Routes, useLocation } from "react-router-dom";
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
import LoginPage from "./pages/LoginPage";
import SettingsPage from "./pages/SettingsPage";
import { useTrafficDataset } from "./hooks/useTrafficDataset";
import { useTrafficDashboardView } from "./hooks/useTrafficDashboardView";
import "./App.scss";

function App() {
  const location = useLocation();
  const tableBaseOrder = location.pathname.startsWith("/sessions")
    ? "newest"
    : "chronological";

  const [processedFilesCount] = React.useState(0);
  const { allData, fetchAllData } = useTrafficDataset();

  const {
    filterSource,
    setFilterSource,
    filterDestination,
    setFilterDestination,
    filterPort,
    setFilterPort,
    filterAnomaly,
    setFilterAnomaly,
    clearFilters,
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
  } = useTrafficDashboardView(allData, { tableBaseOrder });
  const systemStatus = "OK";

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
            <h2>
              {location.pathname === "/login"
                ? "Вход"
                : location.pathname === "/settings"
                  ? "Настройки"
                  : "Network Traffic"}
            </h2>
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
                  paginatedTableGroups={paginatedTableGroups}
                  sortColumn={sortColumn}
                  sortDirection={sortDirection}
                  onSortColumn={cycleTableSort}
                  filterSource={filterSource}
                  filterDestination={filterDestination}
                  filterPort={filterPort}
                  filterAnomaly={filterAnomaly}
                  onFilterSourceChange={setFilterSource}
                  onFilterDestinationChange={setFilterDestination}
                  onFilterPortChange={setFilterPort}
                  onFilterAnomalyChange={setFilterAnomaly}
                  onClearFilters={clearFilters}
                  currentPage={currentPage}
                  totalPages={totalPages || 1}
                  totalRows={trafficTableGroups.length}
                  itemsPerPage={itemsPerPage}
                  onItemsPerPageChange={setItemsPerPage}
                  onPrevPage={() => setCurrentPage((page) => page - 1)}
                  onNextPage={() => setCurrentPage((page) => page + 1)}
                />
              }
            />
            <Route path="/analyze-file" element={<AnalyzeFilePage />} />
            <Route
              path="/settings"
              element={<SettingsPage onAfterAdminMutation={fetchAllData} />}
            />
            <Route path="/login" element={<LoginPage />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </div>
      </div>
    </div>
  );
}

export default App;
