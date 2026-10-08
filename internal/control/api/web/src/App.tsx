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
  manage: (
    <Icon>
      <path d="M12 3l9 5-9 5-9-5 9-5z" />
      <path d="M3 12.5l9 5 9-5M3 16.5l9 5 9-5" />
    </Icon>
  ),
  platform: (
    <Icon>
      <rect x="3" y="4" width="18" height="6.5" rx="1.5" />
      <rect x="3" y="13.5" width="18" height="6.5" rx="1.5" />
      <path d="M7 7.25h.01M7 16.75h.01" />
    </Icon>
  ),
  administration: (
    <Icon>
      <circle cx="9" cy="8" r="3.5" />
      <path d="M2.5 20c.9-3.3 3.4-5 6.5-5s5.6 1.7 6.5 5" />
      <path d="M15.5 4.7a3.5 3.5 0 0 1 0 6.6M18 15.4c1.6.8 2.7 2.4 3.3 4.6" />
    </Icon>
  ),
  signout: (
    <Icon>
      <path d="M14 4H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h7" />
      <path d="M17 8l4 4-4 4M21 12H10" />
    </Icon>
  ),
};

// The sidebar hierarchy, three levels deep. A section (Discover, Assess, …) is
// always open: it is a heading over its modules, not a control. A module
// (Discovery, Scans, …) expands and collapses on its own, independently of its
// siblings. A leaf either renders its own `screen` at `path`, points at the
// screen that already is that module (`to` differs from `path`; `path`
// redirects there, so no screen is duplicated) or at a Pending shell rendered
// at `path`. `data` records what Core holds for a shell today, so the shell
// cannot overclaim: "none" means nothing collects it, "partial" means related
// data exists but no view is built. `perm` mirrors the courtesy hiding for
// reused screens; a shell reads nothing, so it needs none.
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
  children: NavLeaf[];
}
interface NavSection {
  id: string;
  label: string;
  icon: ReactNode;
  children: NavGroup[];
}

const leafTarget = (l: NavLeaf) => l.to ?? l.path;
// The same rule NavLink applies (end=false), so a module's state never
// disagrees with the leaf it holds: /scans/123 still sits under Scans.
const routeMatches = (to: string, pathname: string) => pathname === to || pathname.startsWith(to + "/");

const NAV: NavSection[] = [
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
      {
        id: "assess/scans",
        label: "Scans",
        children: [
          { label: "All Scans", path: "/assess/scans/all", to: "/scans", perm: "scan.read" },
          // The Scans screen opens on its new-scan form; here it is reached as
          // its own page, so the leaf is active rather than All Scans.
          { label: "Create Scan", path: "/assess/scans/create", perm: "scan.create", screen: <Scans /> },
          { label: "Scheduled Scans", path: "/assess/scans/scheduled", data: "none" },
          { label: "Running Scans", path: "/assess/scans/running", data: "partial" },
          { label: "Scan History", path: "/assess/scans/history", data: "partial" },
          { label: "Scan Profiles", path: "/assess/scans/profiles", data: "partial" },
          { label: "Scan Targets", path: "/assess/scans/targets", data: "partial" },
        ],
      },
      {
        id: "assess/vulnerabilities",
        label: "Vulnerabilities",
        children: [
          { label: "All Vulnerabilities", path: "/assess/vulnerabilities/all", to: "/triage", perm: "finding.read" },
          { label: "By Severity", path: "/assess/vulnerabilities/by-severity", data: "partial" },
          { label: "Vulnerability Trends", path: "/assess/vulnerabilities/trends", data: "partial" },
          { label: "Remediation", path: "/assess/vulnerabilities/remediation", data: "partial" },
          { label: "Exceptions / Suppression", path: "/assess/vulnerabilities/exceptions", data: "none" },
          { label: "Baselines", path: "/assess/vulnerabilities/baselines", data: "none" },
          { label: "CVE / CWE Intelligence", path: "/assess/vulnerabilities/intelligence", data: "partial" },
        ],
      },
      {
        id: "assess/sast",
        label: "SAST",
        children: [
          { label: "SAST Scans", path: "/assess/sast/scans", data: "none" },
          { label: "Findings", path: "/assess/sast/findings", data: "none" },
          { label: "Repositories", path: "/assess/sast/repositories", data: "none" },
          { label: "Projects", path: "/assess/sast/projects", data: "none" },
          { label: "Rules", path: "/assess/sast/rules", data: "none" },
          { label: "Baselines", path: "/assess/sast/baselines", data: "none" },
          { label: "Suppressions", path: "/assess/sast/suppressions", data: "none" },
          { label: "Remediation", path: "/assess/sast/remediation", data: "none" },
        ],
      },
      {
        id: "assess/dast",
        label: "DAST",
        children: [
          { label: "Web Applications", path: "/assess/dast/web-applications", data: "none" },
          { label: "API Targets", path: "/assess/dast/api-targets", data: "none" },
          { label: "Findings", path: "/assess/dast/findings", data: "none" },
          { label: "Crawl Results", path: "/assess/dast/crawl-results", data: "none" },
          { label: "Authentication Profiles", path: "/assess/dast/authentication-profiles", data: "none" },
          { label: "Scan Policies", path: "/assess/dast/scan-policies", data: "none" },
        ],
      },
    ],
  },
  {
    id: "manage",
    label: "Manage",
    icon: icons.manage,
    children: [
      {
        id: "manage/risk",
        label: "Risk",
        children: [
          { label: "Risk Overview", path: "/manage/risk/overview", data: "partial" },
          { label: "Asset Risk", path: "/manage/risk/asset-risk", data: "partial" },
          { label: "Business Risk", path: "/manage/risk/business-risk", data: "none" },
          { label: "Exposure Analysis", path: "/manage/risk/exposure-analysis", to: "/exposure", perm: "finding.read" },
          { label: "Risk Trends", path: "/manage/risk/trends", data: "partial" },
          { label: "Prioritization", path: "/manage/risk/prioritization", data: "partial" },
        ],
      },
      {
        id: "manage/remediation",
        label: "Remediation",
        children: [
          { label: "Open Remediation", path: "/manage/remediation/open", data: "partial" },
          { label: "Assigned to Me", path: "/manage/remediation/assigned-to-me", data: "none" },
          { label: "SLA", path: "/manage/remediation/sla", data: "none" },
          { label: "Overdue", path: "/manage/remediation/overdue", data: "none" },
          { label: "Verified Fixes", path: "/manage/remediation/verified-fixes", data: "partial" },
          { label: "Remediation History", path: "/manage/remediation/history", data: "partial" },
        ],
      },
      {
        id: "manage/reports",
        label: "Reports",
        children: [
          { label: "Executive Reports", path: "/manage/reports/executive", data: "none" },
          { label: "Technical Reports", path: "/manage/reports/technical", data: "partial" },
          { label: "Developer Reports", path: "/manage/reports/developer", data: "none" },
          { label: "Compliance Reports", path: "/manage/reports/compliance", data: "none" },
          { label: "Scheduled Reports", path: "/manage/reports/scheduled", data: "none" },
          { label: "Custom Reports", path: "/manage/reports/custom", data: "none" },
        ],
      },
    ],
  },
  {
    id: "platform",
    label: "Platform",
    icon: icons.platform,
    children: [
      {
        id: "platform/policies",
        label: "Policies",
        children: [
          { label: "Scan Policies", path: "/platform/policies/scan", data: "partial" },
          { label: "Security Policies", path: "/platform/policies/security", data: "none" },
          { label: "Risk Policies", path: "/platform/policies/risk", data: "none" },
          { label: "SLA Policies", path: "/platform/policies/sla", data: "none" },
          { label: "Compliance Policies", path: "/platform/policies/compliance", data: "none" },
        ],
      },
    ],
  },
  {
    id: "administration",
    label: "Administration",
    icon: icons.administration,
    children: [
      {
        id: "administration/administration",
        label: "Administration",
        children: [
          { label: "Users", path: "/administration/users", data: "none" },
          { label: "Roles & Permissions", path: "/administration/roles", data: "none" },
          { label: "Organizations / Tenants", path: "/administration/tenants", data: "none" },
          { label: "Credentials / Secrets", path: "/administration/credentials", data: "partial" },
          { label: "Audit Logs", path: "/administration/audit-logs", data: "none" },
          { label: "System Configuration", path: "/administration/system-configuration", data: "none" },
        ],
      },
      {
        id: "administration/settings",
        label: "Settings",
        children: [
          // The existing Settings screen (identity trust, host-key pins, your
          // password) is the general settings page.
          { label: "General", path: "/administration/settings/general", to: "/settings" },
          { label: "Notifications", path: "/administration/settings/notifications", data: "none" },
          { label: "Data Retention", path: "/administration/settings/data-retention", data: "none" },
          { label: "Appearance", path: "/administration/settings/appearance", data: "none" },
        ],
      },
    ],
  },
];

const navLeaves = (): NavLeaf[] => NAV.flatMap((s) => s.children.flatMap((g) => g.children));

// Ids of the modules holding a leaf that matches `pathname`.
const activeGroups = (pathname: string): string[] =>
  NAV.flatMap((s) => s.children)
    .filter((g) => g.children.some((l) => routeMatches(leafTarget(l), pathname)))
    .map((g) => g.id);

// Paths a previous build linked to directly, before their modules gained
// children. Bookmarks keep landing somewhere real.
const LEGACY_REDIRECTS: [string, string][] = [
  ["/assess/scans", "/scans"],
  ["/assess/vulnerabilities", "/triage"],
  ["/assess/sast", "/assess/sast/scans"],
  ["/assess/dast", "/assess/dast/web-applications"],
];

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

  // Arriving at a grouped route opens the module that holds it, so the active
  // leaf is never hidden. Only opens: a module the operator closed elsewhere
  // stays closed until they navigate into it.
  useEffect(() => {
    const need = activeGroups(pathname);
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

  // Expanding or collapsing one module leaves its siblings as they are.
  const toggleGroup = (id: string) => {
    setOpenGroups((cur) => persistGroups(cur.includes(id) ? cur.filter((g) => g !== id) : [...cur, id]));
  };

  // On the collapsed rail a section's modules have no room to show, so its
  // icon expands the sidebar through the hamburger's own persisted path.
  const expandFromRail = () => {
    setTip(null);
    toggleSidebar();
  };

  if (loading) return <div className="center">Loading…</div>;
  if (mustChange) return <ChangePassword />;
  if (!session) return <Login />;

  // Nav items reflect the session's permissions as a courtesy: every route is
  // enforced server-side, and each screen surfaces a 403 if a control was shown
  // that should not have been. Hiding is never the only gate.
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
  const holds = (leaves: NavLeaf[]) => leaves.some((l) => routeMatches(leafTarget(l), pathname));

  const renderGroup = (g: NavGroup): ReactNode => {
    const open = openGroups.includes(g.id);
    const bodyId = `side-group-${g.id.replace(/\//g, "-")}`;
    return (
      <div key={g.id} className="side-group">
        <button
          type="button"
          className={"side-item side-group-head side-group-sub" + (holds(g.children) ? " holds-active" : "")}
          aria-expanded={open}
          aria-controls={bodyId}
          onClick={() => toggleGroup(g.id)}
        >
          <span className="side-label">{g.label}</span>
          <span className={open ? "side-chevron open" : "side-chevron"} aria-hidden="true">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M6 9l6 6 6-6" />
            </svg>
          </span>
        </button>
        {open && (
          <div className="side-children" id={bodyId} role="group" aria-label={g.label}>
            {g.children.filter(visibleLeaf).map((l) => sideItem(leafTarget(l), l.label, null, " side-leaf"))}
          </div>
        )}
      </div>
    );
  };

  // A section is a heading over its modules, always open. Only on the icon
  // rail is it a control, because there its modules cannot show.
  const renderSection = (s: NavSection): ReactNode => {
    const cls = "side-item side-group-head side-section-head" + (holds(s.children.flatMap((g) => g.children)) ? " holds-active" : "");
    const inner = (
      <>
        <span className="side-icon">{s.icon}</span>
        <span className="side-label">{s.label}</span>
      </>
    );
    return (
      <div key={s.id} className="side-group side-section" role="group" aria-label={s.label}>
        {collapsed ? (
          <button type="button" className={cls} aria-label={s.label} onClick={expandFromRail}
            onMouseEnter={showTip(s.label)} onMouseLeave={hideTip}>
            {inner}
          </button>
        ) : (
          <div className={cls}>{inner}</div>
        )}
        <div className="side-children">{s.children.map(renderGroup)}</div>
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
          {sideItem("/", "Dashboard", icons.dashboard)}
          {NAV.map(renderSection)}
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
            {/* The sidebar hierarchy. A leaf with its own screen renders it;
                one that is an existing screen redirects to it; the rest are
                shells until their data exists. */}
            {navLeaves().map((l) => (
              <Route
                key={l.path}
                path={l.path}
                element={l.screen ?? (l.to ? <Navigate to={l.to} replace /> : <Pending title={l.label} data={l.data ?? "none"} />)}
              />
            ))}
            {LEGACY_REDIRECTS.map(([from, to]) => (
              <Route key={from} path={from} element={<Navigate to={to} replace />} />
            ))}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}
