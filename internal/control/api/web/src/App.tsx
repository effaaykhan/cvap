import { useState } from "react";
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

export function App() {
  const { session, loading, mustChange, logout } = useAuth();
  const [theme, setTheme] = useState<"dark" | "light">(readTheme);

  const toggleTheme = () => {
    const next = theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try {
      localStorage.setItem("cvap-theme", next);
    } catch {
      /* a viewer with storage disabled still gets the toggle for this session */
    }
    setTheme(next);
  };

  if (loading) return <div className="center">Loading…</div>;
  if (mustChange) return <ChangePassword />;
  if (!session) return <Login />;

  // The console's five surfaces (design spec, backlog #12): landing first,
  // triage as the centre of gravity, health as its own place. Nav items reflect
  // the session's permissions as a courtesy: every route is enforced server-side,
  // and each screen surfaces a 403 if a control was shown that should not have
  // been. Hiding is never the only gate.
  const canFindings = has(session, "finding.read");
  const nav: [string, string, boolean][] = [
    ["/", "Overview", true],
    ["/triage", "Triage", canFindings],
    ["/assets", "Systems", has(session, "asset.read")],
    ["/scans", "Scans", has(session, "scan.read")],
    ["/health", "Health", has(session, "scan.read")],
    ["/identity", "Identity", has(session, "asset.read")],
    ["/knowledge", "Knowledge", canFindings],
  ];

  return (
    <div className="app">
      <header>
        <span className="brand">CVAP</span>
        <nav>
          {nav.filter(([, , ok]) => ok).map(([to, label]) => (
            <NavLink key={to} to={to} end={to === "/"}>
              {label}
            </NavLink>
          ))}
        </nav>
        <span className="who">
          {has(session, "scan.create") && <Link className="btn small-btn" to="/scans">New scan</Link>}
          <button
            className="theme-toggle"
            onClick={toggleTheme}
            title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
            aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
          >
            {theme === "dark" ? "☀" : "☾"}
          </button>
          <span className="email">{session.email}</span>
          <span className="sep">·</span>
          <Link className="settings" to="/settings">Settings</Link>
          <button className="link" onClick={() => void logout()}>
            Sign out
          </button>
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
  );
}
