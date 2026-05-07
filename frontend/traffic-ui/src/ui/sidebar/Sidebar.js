import React from "react";
import { NavLink } from "react-router-dom";
import "./Sidebar.scss";

function Sidebar({ systemStatus, processedFiles, flowsCount }) {
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
          to="/dashboard"
          className={({ isActive }) =>
            isActive ? "sidebar__link sidebar__link--active" : "sidebar__link"
          }
        >
          Dashboard
        </NavLink>
        <NavLink
          to="/sessions"
          className={({ isActive }) =>
            isActive ? "sidebar__link sidebar__link--active" : "sidebar__link"
          }
        >
          Sessions
        </NavLink>
        <NavLink
          to="/analyze-file"
          className={({ isActive }) =>
            isActive ? "sidebar__link sidebar__link--active" : "sidebar__link"
          }
        >
          Analyze file
        </NavLink>
      </nav>

      <div className="sidebar__status">
        <p className="sidebar__status-title">System Status</p>
        <p className={statusClassName}>{systemStatus}</p>
        <p className="sidebar__metric">Processed files: {processedFiles}</p>
        <p className="sidebar__metric">Flows: {flowsCount}</p>
        <div className="sidebar__operational">
          <span className="sidebar__pulse" />
          <span>All systems operational</span>
        </div>
      </div>
    </aside>
  );
}

export default Sidebar;
