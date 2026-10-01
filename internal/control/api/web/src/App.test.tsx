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

const shells: [string, string, "none" | "partial"][] = [
  ["/discover/discovery/network-discovery", "Network Discovery", "partial"],
  ["/discover/discovery/web-api-discovery", "Web & API Discovery", "none"],
  ["/discover/discovery/cloud-assets", "Cloud Assets", "none"],
  ["/discover/discovery/containers", "Containers", "none"],
  ["/discover/discovery/kubernetes", "Kubernetes", "none"],
  ["/discover/discovery/databases", "Databases", "partial"],
  ["/discover/discovery/network-devices", "Network Devices", "none"],
  ["/discover/discovery/unknown-assets", "Unknown Assets", "partial"],
  ["/discover/discovery/topology", "Asset Relationships / Topology", "none"],
  ["/discover/attack-surface/external", "External Attack Surface", "partial"],
  ["/discover/attack-surface/internal", "Internal Attack Surface", "partial"],
  ["/discover/attack-surface/internet-facing", "Internet-Facing Assets", "partial"],
  ["/discover/attack-surface/exposed-services", "Exposed Services", "partial"],
  ["/discover/attack-surface/shadow-it", "Shadow IT", "none"],
  ["/discover/attack-surface/unknown-unmanaged", "Unknown / Unmanaged Assets", "partial"],
  ["/assess/sast", "SAST", "none"],
  ["/assess/dast", "DAST", "none"],
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
    ["/discover/discovery/asset-inventory", "Systems screen"],
    ["/assess/scans", "Scans screen"],
    ["/assess/vulnerabilities", "Triage screen"],
  ])("%s reuses the existing screen", (path, screenHeading) => {
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

  it("keeps the flat modules after the groups, in their old order", () => {
    renderAt("/");
    const labels = within(sideNav())
      .getAllByRole("link")
      .map((a) => a.textContent);
    expect(labels).toEqual(["Dashboard", "Triage", "Systems", "Scans", "Health", "Identity", "Knowledge"]);
    const heads = within(sideNav())
      .getAllByRole("button")
      .map((b) => b.textContent);
    expect(heads).toEqual(["Discover", "Assess"]);
  });

  it("opens the groups holding the active route, and only those", () => {
    renderAt("/discover/attack-surface/shadow-it");
    const nav = sideNav();
    expect(within(nav).getByRole("button", { name: "Discover" })).toHaveAttribute("aria-expanded", "true");
    expect(within(nav).getByRole("button", { name: "Attack Surface" })).toHaveAttribute("aria-expanded", "true");
    expect(within(nav).getByRole("button", { name: "Discovery" })).toHaveAttribute("aria-expanded", "false");
    expect(within(nav).getByRole("button", { name: "Assess" })).toHaveAttribute("aria-expanded", "false");
    // Group headers are never styled as an active page.
    expect(within(nav).getByRole("button", { name: "Attack Surface" })).not.toHaveClass("active");
  });

  it("expands and collapses groups independently", async () => {
    const user = userEvent.setup();
    renderAt("/");
    const nav = sideNav();
    await user.click(within(nav).getByRole("button", { name: "Discover" }));
    await user.click(within(nav).getByRole("button", { name: "Discovery" }));
    expect(within(nav).getByRole("link", { name: "Kubernetes" })).toBeInTheDocument();
    expect(within(nav).queryByRole("link", { name: "Shadow IT" })).not.toBeInTheDocument();

    await user.click(within(nav).getByRole("button", { name: "Attack Surface" }));
    await user.click(within(nav).getByRole("button", { name: "Discovery" }));
    expect(within(nav).queryByRole("link", { name: "Kubernetes" })).not.toBeInTheDocument();
    expect(within(nav).getByRole("link", { name: "Shadow IT" })).toBeInTheDocument();
    expect(JSON.parse(localStorage.getItem("cvap-nav-groups")!)).toEqual(["discover", "discover/attack-surface"]);
  });

  it("on the collapsed rail a group header expands the sidebar with the group open", async () => {
    localStorage.setItem("cvap-sidebar", "collapsed");
    const user = userEvent.setup();
    const { container } = renderAt("/");
    expect(container.querySelector(".app")).toHaveClass("nav-collapsed");
    await user.click(within(sideNav()).getByRole("button", { name: "Assess" }));
    expect(container.querySelector(".app")).not.toHaveClass("nav-collapsed");
    expect(localStorage.getItem("cvap-sidebar")).toBe("expanded");
    expect(within(sideNav()).getByRole("link", { name: "DAST" })).toBeInTheDocument();
  });

  it("marks the holding group, not a page, when the leaf is active", () => {
    renderAt("/assess/dast");
    expect(within(sideNav()).getByRole("button", { name: "Assess" })).toHaveClass("holds-active");
    expect(within(sideNav()).getByRole("button", { name: "Discover" })).not.toHaveClass("holds-active");
  });

  it("hides reused leaves the session cannot read, as the flat nav does", () => {
    session.permissions = [];
    renderAt("/assess/sast");
    const nav = sideNav();
    expect(within(nav).queryByRole("link", { name: "Scans" })).not.toBeInTheDocument();
    expect(within(nav).queryByRole("link", { name: "Vulnerabilities" })).not.toBeInTheDocument();
    expect(within(nav).getByRole("link", { name: "SAST" })).toBeInTheDocument();
  });

  it("keeps the New scan header action", () => {
    renderAt("/discover/discovery/containers");
    expect(screen.getByRole("link", { name: "New scan" })).toHaveAttribute("href", "/scans");
  });
});
