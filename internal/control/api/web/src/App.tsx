import { useState } from "react";
import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { useAuth } from "./lib/auth";
import { has } from "./lib/api";
import { Login } from "./screens/Login";
import { ChangePassword } from "./screens/ChangePassword";
import { Findings } from "./screens/Findings";
import { FindingDetail } from "./screens/FindingDetail";
import { Assets } from "./screens/Assets";
import { AssetDetail } from "./screens/AssetDetail";
import { Scans } from "./screens/Scans";
import { ScanDetail } from "./screens/ScanDetail";
import { Exposure } from "./screens/Exposure";
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

  // Nav items reflect the session's permissions. This is a courtesy: every route
  // is enforced server-side, and each screen surfaces a 403 if a control was
  // shown that should not have been. Hiding is never the only gate.
  const nav: [string, string, boolean][] = [
    ["/findings", "Findings", has(session, "finding.read")],
    ["/assets", "Assets", has(session, "asset.read")],
    ["/scans", "Scans", has(session, "scan.read")],
    ["/exposure", "Exposure", has(session, "finding.read")],
    // No permission gate: changing your own password is available to any
    // signed-in operator.
    ["/settings", "Settings", true],
  ];

  return (
    <div className="app">
      <header>
        <span className="brand">CVAP</span>
        <nav>
          {nav.filter(([, , ok]) => ok).map(([to, label]) => (
            <NavLink key={to} to={to}>
              {label}
            </NavLink>
          ))}
        </nav>
        <span className="who">
          <button
            className="theme-toggle"
            onClick={toggleTheme}
            title={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
            aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
          >
            {theme === "dark" ? "☀" : "☾"}
          </button>
          <span className="email">{session.email}</span>
          <button className="link" onClick={() => void logout()}>
            Sign out
          </button>
        </span>
      </header>
      <main>
        <Routes>
          <Route path="/findings" element={<Findings />} />
          <Route path="/findings/:id" element={<FindingDetail />} />
          <Route path="/assets" element={<Assets />} />
          <Route path="/assets/:id" element={<AssetDetail />} />
          <Route path="/scans" element={<Scans />} />
          <Route path="/scans/:id" element={<ScanDetail />} />
          <Route path="/exposure" element={<Exposure />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/findings" replace />} />
        </Routes>
      </main>
    </div>
  );
}
