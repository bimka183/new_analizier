import React from "react";
import { NavLink } from "react-router-dom";
import { DASHBOARD_NAV_ENABLED } from "../../constants/trafficApp";
import { useAuth } from "../../context/AuthContext";
import "./Sidebar.scss";

function Sidebar({ systemStatus, processedFiles, flowsCount }) {
  const { user, logout, isAuthenticated } = useAuth();
  const statusClassName =
    systemStatus === "ERROR"
      ? "sidebar__status-value sidebar__status-value--error"
      : "sidebar__status-value sidebar__status-value--ok";

  return (
    <aside className="sidebar">
      <div className="sidebar__logo-block">
        <span className="sidebar__logo">PTA</span>
        <div>
          <p className="sidebar__title">PCAP Traffic Analyzer</p>
          <p className="sidebar__subtitle">Security Dashboard</p>
        </div>
      </div>

      <nav className="sidebar__nav" aria-label="Main navigation">
        <NavLink
          to="/analyze-file"
          className={({ isActive }) =>
            isActive ? "sidebar__link sidebar__link--active" : "sidebar__link"
          }
        >
          Analyze file
        </NavLink>
        {DASHBOARD_NAV_ENABLED ? (
          <NavLink
            to="/dashboard"
            className={({ isActive }) =>
              isActive ? "sidebar__link sidebar__link--active" : "sidebar__link"
            }
          >
            Dashboard
          </NavLink>
        ) : null}
        <NavLink
          to="/sessions"
          className={({ isActive }) =>
            isActive ? "sidebar__link sidebar__link--active" : "sidebar__link"
          }
        >
          Sessions
        </NavLink>
        <NavLink
          to="/settings"
          className={({ isActive }) =>
            isActive ? "sidebar__link sidebar__link--active" : "sidebar__link"
          }
        >
          Settings
        </NavLink>
      </nav>

      <div className="sidebar__status">
        <p className="sidebar__status-title">System Status</p>
        <p className={statusClassName}>{systemStatus}</p>
        <p className="sidebar__metric">Processed files: {processedFiles}</p>
        <p className="sidebar__metric">Flows: {flowsCount}</p>

        <div className="sidebar__account">
          {!isAuthenticated ? (
            <NavLink
              to="/login"
              className={({ isActive }) =>
                isActive
                  ? "sidebar__login-link sidebar__login-link--active"
                  : "sidebar__login-link"
              }
            >
              Войти
            </NavLink>
          ) : (
            <div className="sidebar__profile">
              <div className="sidebar__profile-main">
                <span className="sidebar__profile-avatar" aria-hidden="true">
                  {user.username.slice(0, 2).toUpperCase()}
                </span>
                <div className="sidebar__profile-text">
                  <span className="sidebar__profile-name">{user.username}</span>
                  <span
                    className={`sidebar__profile-role sidebar__profile-role--${user.role}`}
                  >
                    {user.role}
                  </span>
                </div>
              </div>
              <button
                type="button"
                className="sidebar__logout"
                onClick={logout}
              >
                Выйти
              </button>
            </div>
          )}
        </div>

        <div className="sidebar__operational">
          <span className="sidebar__pulse" />
          <span>All systems operational</span>
        </div>
      </div>
    </aside>
  );
}

export default Sidebar;
