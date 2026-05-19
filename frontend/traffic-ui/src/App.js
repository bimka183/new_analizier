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
import Footer from "./ui/footer";
import AnalyzedFilesPage from "./pages/AnalyzedFilesPage";
import AnalyzeFilePage from "./pages/AnalyzeFilePage";
import LoginPage from "./pages/LoginPage";
import SettingsPage from "./pages/SettingsPage";
import { DEFAULT_HOME_ROUTE } from "./constants/trafficApp";
import { useTrafficDataset } from "./hooks/useTrafficDataset";
import { useTrafficDashboardView } from "./hooks/useTrafficDashboardView";
import "./App.scss";

function App() {
  const location = useLocation();

  const [processedFilesCount] = React.useState(0);
  const { allData, fetchAllData } = useTrafficDataset();

  const dashboardView = useTrafficDashboardView(allData, {
    tableBaseOrder: "chronological",
  });

  const handleAfterAdminMutation = React.useCallback(() => {
    fetchAllData();
  }, [fetchAllData]);

  const systemStatus = "OK";

  return (
    <div className="app-shell">
      <Sidebar
        systemStatus={systemStatus}
        processedFiles={processedFilesCount}
        flowsCount={allData.length}
      />
      <div className="app-shell__main">
      <div className="app-shell__content">
        <div className="app">
          <div className="app__header">
            <h2>
              {location.pathname === "/login"
                ? "Вход"
                : location.pathname === "/settings"
                  ? "Настройки"
                  : location.pathname === "/analyzed-files"
                    ? "History"
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
                      threatSummary={dashboardView.threatSummary}
                      threatRowsCount={dashboardView.filteredChartData.length}
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
                    trafficByIP={dashboardView.trafficByIP}
                    anomaliesCount={dashboardView.anomaliesCount}
                    trafficByTime={dashboardView.trafficByTime}
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
                        groups={dashboardView.paginatedTableGroups}
                        sortColumn={dashboardView.sortColumn}
                        sortDirection={dashboardView.sortDirection}
                        onSortColumn={dashboardView.cycleTableSort}
                      />
                      <TrafficPagination
                        currentPage={dashboardView.currentPage}
                        totalPages={dashboardView.totalPages || 1}
                        totalRows={dashboardView.trafficTableGroups.length}
                        itemsPerPage={dashboardView.itemsPerPage}
                        onItemsPerPageChange={dashboardView.setItemsPerPage}
                        onPrev={() =>
                          dashboardView.setCurrentPage((page) => page - 1)
                        }
                        onNext={() =>
                          dashboardView.setCurrentPage((page) => page + 1)
                        }
                      />
                    </div>
                  </section>
                </>
              }
            />
            <Route path="/analyzed-files" element={<AnalyzedFilesPage />} />
            <Route
              path="/sessions"
              element={<Navigate to="/analyzed-files" replace />}
            />
            <Route path="/analyze-file" element={<AnalyzeFilePage />} />
            <Route
              path="/settings"
              element={<SettingsPage onAfterAdminMutation={handleAfterAdminMutation} />}
            />
            <Route path="/login" element={<LoginPage />} />
            <Route path="*" element={<Navigate to={DEFAULT_HOME_ROUTE} replace />} />
          </Routes>
        </div>
      </div>
      <Footer />
      </div>
    </div>
  );
}

export default App;
