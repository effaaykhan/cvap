import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

const session = { email: "op@example.test", permissions: [] as string[] };
vi.mock("./lib/auth", () => ({
  useAuth: () => ({ session, loading: false, mustChange: false, logout: vi.fn() }),
}));
// The screens are stubbed: this file tests navigation and routing, not what
// any screen fetches.
vi.mock("./screens/Overview", () => ({ Overview: () => <h1>Dashboard screen</h1> }));
vi.mock("./screens/Findings", () => ({ Findings: () => <h1>Triage screen</h1> }));
vi.mock("./screens/FindingDetail", () => ({ FindingDetail: () => <h1>Finding screen</h1> }));
vi.mock("./screens/Assets", () => ({ Assets: () => <h1>Systems screen</h1> }));
vi.mock("./screens/AssetDetail", () => ({ AssetDetail: () => <h1>System detail screen</h1> }));
vi.mock("./screens/Health", () => ({ Health: () => <h1>Health screen</h1> }));
vi.mock("./screens/Identity", () => ({ Identity: () => <h1>Identity screen</h1> }));
vi.mock("./screens/Scans", () => ({ Scans: () => <h1>Scans screen</h1> }));
vi.mock("./screens/ScanDetail", () => ({ ScanDetail: () => <h1>Scan detail screen</h1> }));
vi.mock("./screens/Exposure", () => ({ Exposure: () => <h1>Exposure screen</h1> }));
vi.mock("./screens/Knowledge", () => ({ Knowledge: () => <h1>Knowledge screen</h1> }));
vi.mock("./screens/Settings", () => ({ Settings: () => <h1>Settings screen</h1> }));
vi.mock("./screens/AssetInventory", () => ({ AssetInventory: () => <h1>Asset Inventory</h1> }));
vi.mock("./screens/NetworkDiscovery", () => ({ NetworkDiscovery: () => <h1>Network Discovery</h1> }));
vi.mock("./screens/WebDiscovery", () => ({ WebDiscovery: () => <h1>Web &amp; API Discovery</h1> }));
vi.mock("./screens/Databases", () => ({ Databases: () => <h1>Databases</h1> }));
vi.mock("./screens/UnknownAssets", () => ({ UnknownAssets: () => <h1>Unknown Assets</h1> }));

import { App } from "./App";

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  );
}
const heading = () => screen.getByRole("heading", { level: 1 }).textContent;
const sideNav = () => screen.getByRole("navigation");


// Section → module heads, in sidebar order: the hierarchy the operator sees.
const MODULES = [
  "Discovery", "Attack Surface",
  "Scans", "Vulnerabilities", "SAST", "DAST",
  "Risk", "Remediation", "Reports",
  "Policies",
  "Administration", "Settings",
];

const shells: [string, string, "none" | "partial"][] = [
  ["/discover/discovery/cloud-assets", "Cloud Assets", "none"],
  ["/discover/discovery/containers", "Containers", "none"],
  ["/discover/discovery/kubernetes", "Kubernetes", "none"],
  ["/discover/discovery/network-devices", "Network Devices", "none"],
  ["/discover/discovery/topology", "Asset Relationships / Topology", "none"],
  ["/discover/attack-surface/external", "External Attack Surface", "partial"],
  ["/discover/attack-surface/internal", "Internal Attack Surface", "partial"],
  ["/discover/attack-surface/internet-facing", "Internet-Facing Assets", "partial"],
  ["/discover/attack-surface/exposed-services", "Exposed Services", "partial"],
  ["/discover/attack-surface/shadow-it", "Shadow IT", "none"],
  ["/discover/attack-surface/unknown-unmanaged", "Unknown / Unmanaged Assets", "partial"],
  ["/assess/scans/scheduled", "Scheduled Scans", "none"],
  ["/assess/scans/running", "Running Scans", "partial"],
  ["/assess/vulnerabilities/by-severity", "By Severity", "partial"],
  ["/assess/vulnerabilities/exceptions", "Exceptions / Suppression", "none"],
  ["/assess/vulnerabilities/intelligence", "CVE / CWE Intelligence", "partial"],
  ["/assess/sast/repositories", "Repositories", "none"],
  ["/assess/dast/authentication-profiles", "Authentication Profiles", "none"],
  ["/manage/risk/overview", "Risk Overview", "partial"],
  ["/manage/remediation/assigned-to-me", "Assigned to Me", "none"],
  ["/manage/reports/executive", "Executive Reports", "none"],
  ["/platform/policies/scan", "Scan Policies", "partial"],
  ["/platform/policies/compliance", "Compliance Policies", "none"],
  ["/administration/users", "Users", "none"],
  ["/administration/roles", "Roles & Permissions", "none"],
  ["/administration/credentials", "Credentials / Secrets", "partial"],
  ["/administration/audit-logs", "Audit Logs", "none"],
  ["/administration/settings/notifications", "Notifications", "none"],
  ["/administration/settings/appearance", "Appearance", "none"],
];

describe("App navigation", () => {
  beforeEach(() => {
    localStorage.clear();
    session.permissions = ["finding.read", "asset.read", "scan.read", "scan.create"];
  });

  it.each(shells)("%s renders the %s shell without data", (path, title, data) => {
    renderAt(path);
    expect(heading()).toBe(title);
    expect(
      screen.getByText(data === "none" ? "No current backend data available." : /Not built yet/),
    ).toBeInTheDocument();
    // The active leaf is visible with the existing active styling.
    expect(within(sideNav()).getByRole("link", { name: title })).toHaveClass("active");
  });

  it.each([
    ["/discover/discovery/asset-inventory", "Asset Inventory"],
    ["/discover/discovery/network-discovery", "Network Discovery"],
    ["/discover/discovery/web-api-discovery", "Web & API Discovery"],
    ["/discover/discovery/databases", "Databases"],
    ["/discover/discovery/unknown-assets", "Unknown Assets"],
  ])("%s renders its Discovery screen, active in the nav", (path, title) => {
    renderAt(path);
    expect(heading()).toBe(title);
    expect(within(sideNav()).getByRole("link", { name: title })).toHaveClass("active");
  });

  it.each([
    ["/assess/scans/all", "Scans screen", "All Scans"],
    ["/assess/vulnerabilities/all", "Triage screen", "All Vulnerabilities"],
    ["/manage/risk/exposure-analysis", "Exposure screen", "Exposure Analysis"],
    ["/administration/settings/general", "Settings screen", "General"],
  ])("%s reuses the existing screen, with its leaf active", (path, screenHeading, leaf) => {
    renderAt(path);
    expect(heading()).toBe(screenHeading);
    expect(within(sideNav()).getByRole("link", { name: leaf })).toHaveClass("active");
  });

  it("Create Scan is the existing Scans screen at its own address", () => {
    renderAt("/assess/scans/create");
    expect(heading()).toBe("Scans screen");
    expect(within(sideNav()).getByRole("link", { name: "Create Scan" })).toHaveClass("active");
    expect(within(sideNav()).getByRole("link", { name: "All Scans" })).not.toHaveClass("active");
  });

  it.each([
    ["/assess/scans", "Scans screen"],
    ["/assess/vulnerabilities", "Triage screen"],
    ["/assess/sast", "SAST Scans"],
    ["/assess/dast", "Web Applications"],
  ])("old module address %s still lands somewhere real", (path, screenHeading) => {
    renderAt(path);
    expect(heading()).toBe(screenHeading);
  });

  it.each([
    ["/", "Dashboard screen"],
    ["/triage", "Triage screen"],
    ["/findings", "Triage screen"],
    ["/findings/f1", "Finding screen"],
    ["/assets", "Systems screen"],
    ["/assets/a1", "System detail screen"],
    ["/health", "Health screen"],
    ["/identity", "Identity screen"],
    ["/scans", "Scans screen"],
    ["/scans/s1", "Scan detail screen"],
    ["/exposure", "Exposure screen"],
    ["/knowledge", "Knowledge screen"],
    ["/settings", "Settings screen"],
    ["/no-such-page", "Dashboard screen"],
  ])("existing route %s still resolves", (path, screenHeading) => {
    renderAt(path);
    expect(heading()).toBe(screenHeading);
  });

  it("shows Dashboard, then every section with its modules, and none of the old flat items", () => {
    renderAt("/");
    const nav = sideNav();
    expect(within(nav).getAllByRole("link").map((a) => a.textContent)).toEqual(["Dashboard"]);
    expect(within(nav).getAllByRole("button").map((b) => b.textContent)).toEqual(MODULES);
    // A section is a heading over its modules, open without a click.
    for (const s of ["Discover", "Assess", "Manage", "Platform", "Administration"]) {
      expect(within(nav).getByRole("group", { name: s })).toBeInTheDocument();
    }
    for (const gone of ["Triage", "Systems", "Health", "Identity", "Knowledge"]) {
      expect(within(nav).queryByRole("link", { name: gone })).not.toBeInTheDocument();
    }
    // The old standalone Scans item is gone; Scans is a module now.
    expect(within(nav).queryByRole("link", { name: "Scans" })).not.toBeInTheDocument();
  });

  it("opens the module holding the active route, and only that one", () => {
    renderAt("/discover/attack-surface/shadow-it");
    const nav = sideNav();
    expect(within(nav).getByRole("button", { name: "Attack Surface" })).toHaveAttribute("aria-expanded", "true");
    for (const m of MODULES.filter((m) => m !== "Attack Surface")) {
      expect(within(nav).getByRole("button", { name: m })).toHaveAttribute("aria-expanded", "false");
    }
    // Module headers are never styled as an active page.
    expect(within(nav).getByRole("button", { name: "Attack Surface" })).not.toHaveClass("active");
  });

  it("expands and collapses modules independently of their siblings", async () => {
    const user = userEvent.setup();
    renderAt("/");
    const nav = sideNav();
    await user.click(within(nav).getByRole("button", { name: "Discovery" }));
    await user.click(within(nav).getByRole("button", { name: "Attack Surface" }));
    await user.click(within(nav).getByRole("button", { name: "Scans" }));
    // Opening a sibling hid nothing.
    expect(within(nav).getByRole("link", { name: "Kubernetes" })).toBeInTheDocument();
    expect(within(nav).getByRole("link", { name: "Shadow IT" })).toBeInTheDocument();
    expect(within(nav).getByRole("link", { name: "Scan Targets" })).toBeInTheDocument();
    // Every module head stays visible whatever is open.
    expect(within(nav).getAllByRole("button").map((b) => b.textContent)).toEqual(MODULES);

    await user.click(within(nav).getByRole("button", { name: "Discovery" }));
    expect(within(nav).queryByRole("link", { name: "Kubernetes" })).not.toBeInTheDocument();
    expect(within(nav).getByRole("link", { name: "Shadow IT" })).toBeInTheDocument();
    expect(within(nav).getByRole("link", { name: "Scan Targets" })).toBeInTheDocument();
    expect(JSON.parse(localStorage.getItem("cvap-nav-groups")!)).toEqual(["discover/attack-surface", "assess/scans"]);
  });

  it("keeps Administration and Settings as separate modules", async () => {
    const user = userEvent.setup();
    renderAt("/");
    const nav = sideNav();
    await user.click(within(nav).getByRole("button", { name: "Settings" }));
    expect(within(nav).getByRole("link", { name: "Data Retention" })).toBeInTheDocument();
    expect(within(nav).queryByRole("link", { name: "Users" })).not.toBeInTheDocument();
    await user.click(within(nav).getByRole("button", { name: "Administration" }));
    expect(within(nav).getByRole("link", { name: "Users" })).toBeInTheDocument();
    expect(within(nav).getByRole("link", { name: "Data Retention" })).toBeInTheDocument();
  });

  it("on the collapsed rail a section icon expands the sidebar with its modules showing", async () => {
    localStorage.setItem("cvap-sidebar", "collapsed");
    const user = userEvent.setup();
    const { container } = renderAt("/");
    expect(container.querySelector(".app")).toHaveClass("nav-collapsed");
    await user.click(within(sideNav()).getByRole("button", { name: "Assess" }));
    expect(container.querySelector(".app")).not.toHaveClass("nav-collapsed");
    expect(localStorage.getItem("cvap-sidebar")).toBe("expanded");
    expect(within(sideNav()).getByRole("button", { name: "DAST" })).toBeInTheDocument();
  });

  it("marks the holding section on the rail, and the holding module, when a leaf is active", () => {
    localStorage.setItem("cvap-sidebar", "collapsed");
    const { unmount } = renderAt("/assess/dast/findings");
    expect(within(sideNav()).getByRole("button", { name: "Assess" })).toHaveClass("holds-active");
    expect(within(sideNav()).getByRole("button", { name: "Discover" })).not.toHaveClass("holds-active");
    unmount();
    localStorage.setItem("cvap-sidebar", "expanded");
    renderAt("/assess/dast/findings");
    expect(within(sideNav()).getByRole("button", { name: "DAST" })).toHaveClass("holds-active");
    expect(within(sideNav()).getByRole("button", { name: "SAST" })).not.toHaveClass("holds-active");
  });

  it("hides reused leaves the session cannot read", async () => {
    session.permissions = [];
    const user = userEvent.setup();
    renderAt("/");
    const nav = sideNav();
    for (const m of ["Scans", "Vulnerabilities", "Risk"]) await user.click(within(nav).getByRole("button", { name: m }));
    for (const hidden of ["All Scans", "Create Scan", "All Vulnerabilities", "Exposure Analysis"]) {
      expect(within(nav).queryByRole("link", { name: hidden })).not.toBeInTheDocument();
    }
    expect(within(nav).getByRole("link", { name: "Scheduled Scans" })).toBeInTheDocument();
    expect(within(nav).getByRole("link", { name: "Risk Overview" })).toBeInTheDocument();
  });

  it("keeps the New scan header action and the pinned Settings and Sign out", () => {
    renderAt("/discover/discovery/containers");
    expect(screen.getByRole("link", { name: "New scan" })).toHaveAttribute("href", "/scans");
    expect(screen.getByRole("link", { name: "Settings" })).toHaveAttribute("href", "/settings");
    expect(screen.getByRole("button", { name: "Sign out" })).toBeInTheDocument();
  });
});
