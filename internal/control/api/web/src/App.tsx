import { useEffect, useState, type MouseEvent, type ReactNode } from "react";
import { Link, NavLink, Navigate, Route, Routes, useLocation } from "react-router-dom";
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
import { Pending } from "./screens/Pending";
import { AssetInventory } from "./screens/AssetInventory";
import { NetworkDiscovery } from "./screens/NetworkDiscovery";
import { WebDiscovery } from "./screens/WebDiscovery";
import { Databases } from "./screens/Databases";
import { UnknownAssets } from "./screens/UnknownAssets";

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

function readOpenGroups(): string[] {
  try {
    const v: unknown = JSON.parse(localStorage.getItem("cvap-nav-groups") ?? "[]");
    return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
  } catch {
    return [];
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
  discover: (
    <Icon>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M15.5 8.5l-2 5-5 2 2-5 5-2z" />
    </Icon>
  ),
  assess: (
    <Icon>
      <rect x="5" y="4.5" width="14" height="16.5" rx="1.5" />
      <path d="M9 4.5V3h6v1.5M9 13l2 2 4-4" />
    </Icon>
  ),
  signout: (
    <Icon>
      <path d="M14 4H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h7" />
      <path d="M17 8l4 4-4 4M21 12H10" />
    </Icon>
  ),
};

// The grouped part of the sidebar. A leaf either renders its own `screen` at
// `path`, points at the screen that already is that module (`to` differs from
// `path`; `path` redirects there, so no screen is duplicated) or at a Pending
// shell rendered at `path`. `data`
// records what Core holds for a shell today, so the shell cannot overclaim:
// "none" means nothing collects it, "partial" means related data exists but
// no view is built. `perm` mirrors the flat nav's courtesy hiding for reused
// screens; a shell reads nothing, so it needs none.
interface NavLeaf {
  label: string;
  path: string;
  to?: string;
  perm?: string;
  data?: "none" | "partial";
  screen?: ReactNode;
}
interface NavGroup {
  id: string;
  label: string;
  icon?: ReactNode;
  children: (NavGroup | NavLeaf)[];
}

const isGroup = (n: NavGroup | NavLeaf): n is NavGroup => "children" in n;
const leafTarget = (l: NavLeaf) => l.to ?? l.path;
// The same rule NavLink applies (end=false), so a group's state never
// disagrees with the leaf it holds: /assets/123 still sits under Systems.
const routeMatches = (to: string, pathname: string) => pathname === to || pathname.startsWith(to + "/");

const NAV_GROUPS: NavGroup[] = [
  {
    id: "discover",
    label: "Discover",
    icon: icons.discover,
    children: [
      {
        id: "discover/discovery",
        label: "Discovery",
        children: [
          { label: "Asset Inventory", path: "/discover/discovery/asset-inventory", perm: "asset.read", screen: <AssetInventory /> },
          { label: "Network Discovery", path: "/discover/discovery/network-discovery", perm: "scan.read", screen: <NetworkDiscovery /> },
          { label: "Web & API Discovery", path: "/discover/discovery/web-api-discovery", perm: "asset.read", screen: <WebDiscovery /> },
          { label: "Cloud Assets", path: "/discover/discovery/cloud-assets", data: "none" },
          { label: "Containers", path: "/discover/discovery/containers", data: "none" },
          { label: "Kubernetes", path: "/discover/discovery/kubernetes", data: "none" },
          { label: "Databases", path: "/discover/discovery/databases", perm: "asset.read", screen: <Databases /> },
          { label: "Network Devices", path: "/discover/discovery/network-devices", data: "none" },
          { label: "Unknown Assets", path: "/discover/discovery/unknown-assets", perm: "asset.read", screen: <UnknownAssets /> },
          { label: "Asset Relationships / Topology", path: "/discover/discovery/topology", data: "none" },
        ],
      },
      {
        id: "discover/attack-surface",
        label: "Attack Surface",
        children: [
          { label: "External Attack Surface", path: "/discover/attack-surface/external", data: "partial" },
          { label: "Internal Attack Surface", path: "/discover/attack-surface/internal", data: "partial" },
          { label: "Internet-Facing Assets", path: "/discover/attack-surface/internet-facing", data: "partial" },
          { label: "Exposed Services", path: "/discover/attack-surface/exposed-services", data: "partial" },
          { label: "Shadow IT", path: "/discover/attack-surface/shadow-it", data: "none" },
          { label: "Unknown / Unmanaged Assets", path: "/discover/attack-surface/unknown-unmanaged", data: "partial" },
        ],
      },
    ],
  },
  {
    id: "assess",
    label: "Assess",
    icon: icons.assess,
    children: [
      { label: "Scans", path: "/assess/scans", to: "/scans", perm: "scan.read" },
      { label: "Vulnerabilities", path: "/assess/vulnerabilities", to: "/triage", perm: "finding.read" },
      { label: "SAST", path: "/assess/sast", data: "none" },
      { label: "DAST", path: "/assess/dast", data: "none" },
    ],
  },
];

function navLeaves(nodes: (NavGroup | NavLeaf)[]): NavLeaf[] {
  return nodes.flatMap((n) => (isGroup(n) ? navLeaves(n.children) : [n]));
}

// Ids of every group on the path to a leaf matching `pathname`.
function activeGroups(nodes: (NavGroup | NavLeaf)[], pathname: string): string[] {
  return nodes.flatMap((n) => {
    if (!isGroup(n)) return [];
    const inner = activeGroups(n.children, pathname);
    const direct = n.children.some((c) => !isGroup(c) && routeMatches(leafTarget(c), pathname));
    return direct || inner.length > 0 ? [n.id, ...inner] : [];
  });
}

export function App() {
  const { session, loading, mustChange, logout } = useAuth();
  const [theme, setTheme] = useState<"dark" | "light">(readTheme);
  const [collapsed, setCollapsed] = useState<boolean>(readCollapsed);
  const [openGroups, setOpenGroups] = useState<string[]>(readOpenGroups);
  const { pathname } = useLocation();

  const persistGroups = (next: string[]) => {
    try {
      localStorage.setItem("cvap-nav-groups", JSON.stringify(next));
    } catch {
      /* same courtesy as the sidebar toggle */
    }
    return next;
  };

  // Arriving at a grouped route opens the groups that hold it, so the active
  // leaf is never hidden. Only opens: a group the operator closed elsewhere
  // stays closed until they navigate into it.
  useEffect(() => {
    const need = activeGroups(NAV_GROUPS, pathname);
    setOpenGroups((cur) => (need.every((g) => cur.includes(g)) ? cur : persistGroups([...new Set([...cur, ...need])])));
  }, [pathname]);

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

  // On the collapsed rail a group's children have no room to show, so its
  // header expands the sidebar (the hamburger's own persisted path) with the
  // group open, rather than toggling a list nobody can see.
  const toggleGroup = (id: string) => {
    if (collapsed) {
      setTip(null);
      toggleSidebar();
      setOpenGroups((cur) => (cur.includes(id) ? cur : persistGroups([...cur, id])));
      return;
    }
    setOpenGroups((cur) => persistGroups(cur.includes(id) ? cur.filter((g) => g !== id) : [...cur, id]));
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
  const nav: [string, string, boolean, ReactNode][] = [
    ["/", "Dashboard", true, icons.dashboard],
    ["/triage", "Triage", canFindings, icons.triage],
    ["/assets", "Systems", has(session, "asset.read"), icons.systems],
    ["/scans", "Scans", has(session, "scan.read"), icons.scans],
    ["/health", "Health", has(session, "scan.read"), icons.health],
    ["/identity", "Identity", has(session, "asset.read"), icons.identity],
    ["/knowledge", "Knowledge", canFindings, icons.knowledge],
  ];

  const sideItem = (to: string, label: string, icon: ReactNode | null, extra = "") => (
    <NavLink
      key={to}
      to={to}
      end={to === "/"}
      className={"side-item" + extra}
      aria-label={collapsed ? label : undefined}
      onMouseEnter={showTip(label)}
      onMouseLeave={hideTip}
    >
      {icon && <span className="side-icon">{icon}</span>}
      <span className="side-label">{label}</span>
    </NavLink>
  );

  const visibleLeaf = (l: NavLeaf) => !l.perm || has(session, l.perm);
  const renderGroup = (g: NavGroup, top: boolean): ReactNode => {
    const open = openGroups.includes(g.id);
    const holdsActive = navLeaves(g.children).some((l) => routeMatches(leafTarget(l), pathname));
    const bodyId = `side-group-${g.id.replace("/", "-")}`;
    return (
      <div key={g.id} className="side-group">
        <button
          type="button"
          className={"side-item side-group-head" + (holdsActive ? " holds-active" : "") + (top ? "" : " side-group-sub")}
          aria-expanded={open}
          aria-controls={bodyId}
          aria-label={collapsed ? g.label : undefined}
          onClick={() => toggleGroup(g.id)}
          onMouseEnter={showTip(g.label)}
          onMouseLeave={hideTip}
        >
          {g.icon && <span className="side-icon">{g.icon}</span>}
          <span className="side-label">{g.label}</span>
          <span className={open ? "side-chevron open" : "side-chevron"} aria-hidden="true">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M6 9l6 6 6-6" />
            </svg>
          </span>
        </button>
        {open && (
          <div className="side-children" id={bodyId} role="group" aria-label={g.label}>
            {g.children.map((c) =>
              isGroup(c) ? renderGroup(c, false) : visibleLeaf(c) && sideItem(leafTarget(c), c.label, null, " side-leaf"),
            )}
          </div>
        )}
      </div>
    );
  };

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
          {/* Dashboard, then the Discover / Assess groups, then the flat
              modules exactly as before. */}
          {nav.slice(0, 1).filter(([, , ok]) => ok).map(([to, label, , icon]) => sideItem(to, label, icon))}
          {NAV_GROUPS.map((g) => renderGroup(g, true))}
          {nav.slice(1).filter(([, , ok]) => ok).map(([to, label, , icon]) => sideItem(to, label, icon))}
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
            {/* Discover / Assess. A leaf with its own screen renders it; one
                that is an existing screen redirects to it; the rest are shells
                until their data exists. */}
            {navLeaves(NAV_GROUPS).map((l) => (
              <Route
                key={l.path}
                path={l.path}
                element={l.screen ?? (l.to ? <Navigate to={l.to} replace /> : <Pending title={l.label} data={l.data ?? "none"} />)}
              />
            ))}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}
