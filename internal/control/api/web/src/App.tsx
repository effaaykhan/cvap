import { useState, type MouseEvent, type ReactNode } from "react";
import { Link, NavLink, Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./lib/auth";
import { has } from "./lib/api";
import { Login } from "./screens/Login";
import { ChangePassword } from "./screens/ChangePassword";
import { Overview } from "./screens/Overview";
import { Findings } from "./screens/Findings";
import { FindingDetail } from "./screens/FindingDetail";
import { Assets } from "./screens/Assets";
import { AssetDetail } from "./screens/AssetDetail";
import { Health } from "./screens/Health";
import { Identity } from "./screens/Identity";
import { Scans } from "./screens/Scans";
import { ScanDetail } from "./screens/ScanDetail";
import { Exposure } from "./screens/Exposure";
import { Knowledge } from "./screens/Knowledge";
import { Settings } from "./screens/Settings";

function readTheme(): "dark" | "light" {
  try {
    return document.documentElement.dataset.theme === "light" ? "light" : "dark";
  } catch {
    return "dark";
  }
}

function readCollapsed(): boolean {
  try {
    return localStorage.getItem("cvap-sidebar") === "collapsed";
  } catch {
    return false;
  }
}

// Outline icons, one visual weight throughout: 24px grid, 1.6px stroke,
// currentColor so active/hover states colour them for free. Inline because the
// console has no icon dependency and does not want one.
function Icon({ children }: { children: ReactNode }) {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {children}
    </svg>
  );
}

const icons = {
  dashboard: (
    <Icon>
      <rect x="3" y="3" width="7.5" height="7.5" rx="1.5" />
      <rect x="13.5" y="3" width="7.5" height="7.5" rx="1.5" />
      <rect x="3" y="13.5" width="7.5" height="7.5" rx="1.5" />
      <rect x="13.5" y="13.5" width="7.5" height="7.5" rx="1.5" />
    </Icon>
  ),
  triage: (
    <Icon>
      <path d="M12 3l7.5 3v5.2c0 4.5-3.2 8.1-7.5 9.8-4.3-1.7-7.5-5.3-7.5-9.8V6l7.5-3z" />
    </Icon>
  ),
  systems: (
    <Icon>
      <rect x="3" y="4.5" width="18" height="12" rx="1.5" />
      <path d="M9 20.5h6M12 16.5v4" />
    </Icon>
  ),
  scans: (
    <Icon>
      <circle cx="10.5" cy="10.5" r="6.5" />
      <path d="M15.3 15.3L21 21" />
    </Icon>
  ),
  health: (
    <Icon>
      <path d="M3 12h4l2.5-6 4 12 2.5-6h5" />
    </Icon>
  ),
  identity: (
    <Icon>
      <circle cx="12" cy="8" r="4" />
      <path d="M4.5 20.5c1.2-3.6 4.1-5.5 7.5-5.5s6.3 1.9 7.5 5.5" />
    </Icon>
  ),
  knowledge: (
    <Icon>
      <path d="M4 5.5A2.5 2.5 0 0 1 6.5 3H20v15.5H6.5A2.5 2.5 0 0 0 4 21V5.5z" />
      <path d="M4 18.5A2.5 2.5 0 0 1 6.5 16H20" />
    </Icon>
  ),
  settings: (
    <Icon>
      <circle cx="12" cy="12" r="3.2" />
      <path d="M19.4 13.5a7.6 7.6 0 0 0 0-3l2-1.5-2-3.5-2.4.9a7.6 7.6 0 0 0-2.6-1.5L14 2.5h-4l-.4 2.4A7.6 7.6 0 0 0 7 6.4l-2.4-.9-2 3.5 2 1.5a7.6 7.6 0 0 0 0 3l-2 1.5 2 3.5 2.4-.9a7.6 7.6 0 0 0 2.6 1.5l.4 2.4h4l.4-2.4a7.6 7.6 0 0 0 2.6-1.5l2.4.9 2-3.5-2-1.5z" />
    </Icon>
  ),
  signout: (
    <Icon>
      <path d="M14 4H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h7" />
      <path d="M17 8l4 4-4 4M21 12H10" />
    </Icon>
  ),
};

export function App() {
  const { session, loading, mustChange, logout } = useAuth();
  const [theme, setTheme] = useState<"dark" | "light">(readTheme);
  const [collapsed, setCollapsed] = useState<boolean>(readCollapsed);

  const applyTheme = (next: "dark" | "light") => {
    document.documentElement.dataset.theme = next;
    try {
      localStorage.setItem("cvap-theme", next);
    } catch {
      /* a viewer with storage disabled still gets the toggle for this session */
    }
    setTheme(next);
  };

  const toggleSidebar = () => {
    setCollapsed((c) => {
      try {
        localStorage.setItem("cvap-sidebar", c ? "expanded" : "collapsed");
      } catch {
        /* same courtesy: the toggle still works for this session */
      }
      return !c;
    });
  };

  // Clicking the page outside an expanded sidebar collapses it, through the
  // same persisted path as the hamburger. Navigation itself no longer does.
  const collapseOnOutsideClick = () => {
    if (!collapsed) toggleSidebar();
  };

  // Collapsed-rail tooltip: one fixed-position element rendered from state,
  // because .sidebar/.side-item clip with overflow:hidden and the native
  // title tooltip is too slow to appear.
  const [tip, setTip] = useState<{ label: string; top: number; left: number } | null>(null);
  const showTip = (label: string) => (e: MouseEvent<HTMLElement>) => {
    if (!collapsed) return;
    const r = e.currentTarget.getBoundingClientRect();
    setTip({ label, top: r.top + r.height / 2, left: r.right + 10 });
  };
  const hideTip = () => setTip(null);

  if (loading) return <div className="center">Loading…</div>;
  if (mustChange) return <ChangePassword />;
  if (!session) return <Login />;

  // The console's five surfaces (design spec, backlog #12): landing first,
  // triage as the centre of gravity, health as its own place. Nav items reflect
  // the session's permissions as a courtesy: every route is enforced server-side,
  // and each screen surfaces a 403 if a control was shown that should not have
  // been. Hiding is never the only gate.
  const canFindings = has(session, "finding.read");
  const nav: [string, string, boolean, ReactNode][] = [
    ["/", "Dashboard", true, icons.dashboard],
    ["/triage", "Triage", canFindings, icons.triage],
    ["/assets", "Systems", has(session, "asset.read"), icons.systems],
    ["/scans", "Scans", has(session, "scan.read"), icons.scans],
    ["/health", "Health", has(session, "scan.read"), icons.health],
    ["/identity", "Identity", has(session, "asset.read"), icons.identity],
    ["/knowledge", "Knowledge", canFindings, icons.knowledge],
  ];

  return (
    <div className={collapsed ? "app nav-collapsed" : "app"}>
      <aside className="sidebar">
        <div className="sidebar-top">
          <button
            className="hamburger"
            onClick={toggleSidebar}
            aria-expanded={!collapsed}
            aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
            title={collapsed ? "Expand navigation" : "Collapse navigation"}
          >
            <Icon>
              <path d="M4 6.5h16M4 12h16M4 17.5h16" />
            </Icon>
          </button>
          <span className="brand">CVAP</span>
        </div>
        <nav className="side-nav">
          {nav.filter(([, , ok]) => ok).map(([to, label, , icon]) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              className="side-item"
              aria-label={collapsed ? label : undefined}
              onMouseEnter={showTip(label)}
              onMouseLeave={hideTip}
            >
              <span className="side-icon">{icon}</span>
              <span className="side-label">{label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <NavLink
            to="/settings"
            className="side-item"
            aria-label={collapsed ? "Settings" : undefined}
            onMouseEnter={showTip("Settings")}
            onMouseLeave={hideTip}
          >
            <span className="side-icon">{icons.settings}</span>
            <span className="side-label">Settings</span>
          </NavLink>
          <button
            className="side-item"
            onClick={() => void logout()}
            aria-label={collapsed ? "Sign out" : undefined}
            onMouseEnter={showTip("Sign out")}
            onMouseLeave={hideTip}
          >
            <span className="side-icon">{icons.signout}</span>
            <span className="side-label">Sign out</span>
          </button>
        </div>
      </aside>
      {collapsed && tip && (
        <div className="side-tip" role="tooltip" style={{ top: tip.top, left: tip.left }}>
          {tip.label}
        </div>
      )}
      <div className="main-col" onClick={collapseOnOutsideClick}>
        <header>
          <span className="who">
            {has(session, "scan.create") && <Link className="new-scan" to="/scans">New scan</Link>}
            <span className="theme-seg" role="group" aria-label="Theme">
              <button
                className={theme === "light" ? "on" : ""}
                onClick={() => applyTheme("light")}
                aria-pressed={theme === "light"}
                aria-label="Light theme"
                title="Light theme"
              >
                <Icon>
                  <circle cx="12" cy="12" r="4" />
                  <path d="M12 2.5v2.5M12 19v2.5M2.5 12H5M19 12h2.5M5.3 5.3L7 7M17 17l1.7 1.7M18.7 5.3L17 7M7 17l-1.7 1.7" />
                </Icon>
              </button>
              <button
                className={theme === "dark" ? "on" : ""}
                onClick={() => applyTheme("dark")}
                aria-pressed={theme === "dark"}
                aria-label="Dark theme"
                title="Dark theme"
              >
                <Icon>
                  <path d="M20.5 14.5A8.5 8.5 0 0 1 9.5 3.5a8.5 8.5 0 1 0 11 11z" />
                </Icon>
              </button>
            </span>
            <span className="profile">
              <span className="avatar" aria-hidden="true">
                <Icon>
                  <circle cx="12" cy="9" r="3.5" />
                  <path d="M6 19c1.1-2.9 3.3-4.5 6-4.5s4.9 1.6 6 4.5" />
                </Icon>
              </span>
              <span className="email">{session.email}</span>
            </span>
          </span>
        </header>
        <main className="console">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/triage" element={<Findings />} />
            {/* The old table-per-screen paths keep working: bookmarks and the
                detail crumbs land on the console surface that absorbed them. */}
            <Route path="/findings" element={<Navigate to="/triage" replace />} />
            <Route path="/findings/:id" element={<FindingDetail />} />
            <Route path="/assets" element={<Assets />} />
            <Route path="/assets/:id" element={<AssetDetail />} />
            <Route path="/health" element={<Health />} />
            <Route path="/identity" element={<Identity />} />
            <Route path="/scans" element={<Scans />} />
            <Route path="/scans/:id" element={<ScanDetail />} />
            <Route path="/exposure" element={<Exposure />} />
            <Route path="/knowledge" element={<Knowledge />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}
