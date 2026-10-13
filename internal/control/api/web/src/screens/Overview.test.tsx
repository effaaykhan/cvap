import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const session = { user_id: "u-me", permissions: [] as string[] };
vi.mock("../lib/auth", () => ({ useAuth: () => ({ session }) }));
const api = vi.hoisted(() => ({ listAssets: vi.fn(), openPorts: vi.fn(), listFindings: vi.fn(), getFinding: vi.fn() }));
vi.mock("../lib/api", async (orig) => ({ ...(await orig<typeof import("../lib/api")>()), api }));

import { ApiError } from "../lib/api";
import { Overview } from "./Overview";
import { CategoryView, DashboardSearch, RecentAssetsList, RecentFindingsList } from "./DashboardViews";

const NOW = new Date("2026-10-13T12:00:00Z");
const HOUR = 60 * 60 * 1000;
const ago = (h: number) => new Date(NOW.getTime() - h * HOUR).toISOString();
const uuid = (n: number) => `${n.toString(16).padStart(8, "0")}-0000-4000-8000-000000000000`;
const asset = (n: number, firstSeenHoursAgo: number, extra = {}) => ({
  id: uuid(n), hostname: "", os_family: "", device_type: "", criticality: "unknown", environment: "", fragile: false,
  first_seen: ago(firstSeenHoursAgo), last_seen: ago(0), address: `10.0.0.${n}`, open_findings: 0, kev_findings: 0, advisory_status: "no_release", ...extra,
});
const finding = (n: number, firstSeenHoursAgo: number, severity = "high", extra = {}) => ({
  id: uuid(0xf000 + n), rule: `rule-${n}`, category: "exposure", severity, status: "open", asset_id: uuid(n), asset_hostname: "",
  confidence: 1, exposure_zones: 1, first_seen: ago(firstSeenHoursAgo), last_seen: ago(0), kev: false, priority_basis: "unscored", attack_techniques: [], ...extra,
});
const port = (n: number, service: string) => ({ asset_id: uuid(n), address: `10.0.0.${n}`, hostname: "", port: 3306, protocol: "tcp", service, product: "", identified: true, last_seen: ago(1) });

// Seven assets over two pages: first seen 1h, 2h, 5h, 10h, 20h, 30h and 200h ago.
let assetPages: object[][];
let presence: object;
let findings: object[];
let openPorts: object;

function Where() {
  const l = useLocation();
  return <output data-testid="where">{l.pathname + l.search}</output>;
}
function show(path = "/") {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/dashboard/recent-assets" element={<RecentAssetsList />} />
          <Route path="/dashboard/recent-findings" element={<RecentFindingsList />} />
          <Route path="/dashboard/search" element={<DashboardSearch />} />
          <Route path="/dashboard/categories/:key" element={<CategoryView />} />
          <Route path="*" element={<p>elsewhere</p>} />
        </Routes>
        <Where />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}
const cards = () => within(screen.getByLabelText("Asset categories")).getAllByRole("link");
const card = (label: string) => cards().find((c) => c.querySelector(".so-card-name")?.textContent === label)!;
const value = (label: string) => [card(label).querySelector(".so-card-count")!.textContent, card(label).querySelector(".so-card-share")!.textContent];
const loaded = () => waitFor(() => expect(value("Total Assets")[0]).not.toBe("—"));
const panel = (name: string) => screen.getByLabelText(name);
const bodyRows = (name: string) => within(panel(name)).getAllByRole("row").slice(1).filter((r) => !r.classList.contains("empty"));

beforeEach(() => {
  vi.clearAllMocks();
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW);
  session.permissions = ["asset.read", "finding.read"];
  assetPages = [[asset(1, 1), asset(2, 2), asset(3, 5), asset(4, 10)], [asset(5, 20), asset(6, 30), asset(7, 200)]];
  presence = { present: 4, responder: 1, unknown: 3, total: 8, statement: "" };
  findings = [finding(1, 3, "critical"), finding(2, 1, "low"), finding(3, 50, "medium"), finding(4, 23, "info"), finding(5, 6, "high"), finding(6, 12, "high"), finding(8, 4, "medium"), finding(7, 2000)];
  openPorts = { ports: [port(1, "mysql"), port(1, "postgresql"), port(3, "ssh")], truncated: false, limit: 500 };
  api.listAssets.mockImplementation((q: string) => {
    const p = new URLSearchParams(q);
    const i = p.get("before_id") ? 1 : 0;
    const rows = assetPages[i].filter((a) => !p.get("q") || (a as { address: string }).address.includes(p.get("q")!));
    return Promise.resolve({ assets: rows, address_presence: presence, ...(i === 0 ? { next_before: ago(0), next_id: uuid(4) } : {}) });
  });
  api.openPorts.mockImplementation(() => Promise.resolve(openPorts));
  api.listFindings.mockImplementation(() => Promise.resolve({ findings }));
  api.getFinding.mockImplementation((id: string) => Promise.resolve({ ...findings.find((f) => (f as { id: string }).id === id), source: "network" }));
});
afterEach(() => vi.useRealTimers());

describe("Security Overview layout", () => {
  it("leads with the search bar and the period, then the exact heading and description", async () => {
    show();
    expect(screen.getByRole("searchbox")).toHaveAttribute("placeholder", "Search assets, vulnerabilities, findings...");
    const range = screen.getByLabelText("Time range") as HTMLSelectElement;
    expect(range.selectedOptions[0].textContent).toBe("Last 24 Hours");
    expect([...range.options].map((o) => o.textContent)).toEqual(["Last 24 Hours", "Last 3 Days", "Last 7 Days", "Last 15 Days", "Last 30 Days", "Last 60 Days", "Last 90 Days"]);
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(/^Security Overview$/);
    expect(screen.getByText("Real-time visibility of your assets, security posture, and application security across your environment.")).toBeInTheDocument();
    await loaded();
  });

  it("shows the twelve cards in order, each with its icon in its colour", async () => {
    show();
    await loaded();
    expect(cards().map((c) => c.querySelector(".so-card-name")!.textContent)).toEqual([
      "Total Assets", "IP Addresses", "Servers", "Laptops", "APIs", "Web Applications",
      "Docker Containers", "Kubernetes Clusters", "Databases", "Cloud Assets", "Network Devices", "Other Assets",
    ]);
    expect(cards().map((c) => c.querySelector("svg")!.getAttribute("data-icon"))).toEqual([
      "boxes", "network", "server", "laptop", "plug", "globe", "container", "layers", "database", "cloud", "router", "shapes",
    ]);
    expect(card("Databases").querySelector("svg")).toHaveAttribute("stroke", "#F43F5E");
    expect(card("Network Devices").querySelector("svg")).toHaveAttribute("stroke", "#06B6D4");
  });

  it("keeps the Asset Map panel blank", async () => {
    show();
    await loaded();
    const map = panel("Asset Map");
    expect(within(map).getByRole("heading")).toHaveTextContent("Asset Map");
    expect(map.querySelector(".so-map-body")!.childElementCount).toBe(0);
    expect(map.querySelector(".so-map-body")!.textContent).toBe("");
  });
});

describe("Security Overview counts and shares", () => {
  it("counts every asset page, the address total, and database hosts; the rest read —", async () => {
    show();
    await loaded();
    expect(value("Total Assets")).toEqual(["7", "100%"]);
    expect(value("IP Addresses")).toEqual(["8", "—"]);
    // One host with two database engines is one database host: 1 of 7.
    expect(value("Databases")).toEqual(["1", "14%"]);
    for (const l of ["Servers", "Laptops", "APIs", "Web Applications", "Docker Containers", "Kubernetes Clusters", "Cloud Assets", "Network Devices", "Other Assets"]) {
      expect(value(l)).toEqual(["—", "—"]);
      expect(card(l)).toHaveAttribute("title", expect.stringContaining("Not yet integrated"));
    }
    expect(api.listAssets).toHaveBeenCalledTimes(2);
  });

  it("repeats the card values in the legend, in the same order, and draws only measured slices", async () => {
    show();
    await loaded();
    const legend = within(screen.getByLabelText("Distribution legend")).getAllByRole("listitem");
    expect(legend.map((li) => li.textContent)).toEqual(cards().map((c) => c.querySelector(".so-card-name")!.textContent! + c.querySelector(".so-card-count")!.textContent + c.querySelector(".so-card-share")!.textContent));
    const ring = panel("Asset Distribution").querySelector("svg")!;
    expect([...ring.querySelectorAll("[data-segment]")].map((s) => s.getAttribute("data-segment"))).toEqual(["databases"]);
    expect(ring.querySelector(".so-ring-value")).toHaveTextContent("7");
  });

  it("reads Databases as — when the open-port list was capped, never as its partial count", async () => {
    openPorts = { ...openPorts, truncated: true };
    show();
    await loaded();
    expect(value("Databases")).toEqual(["—", "—"]);
    expect(card("Databases")).toHaveAttribute("title", expect.stringContaining("At least 1"));
  });

  it("shows a measured zero as 0", async () => {
    openPorts = { ports: [], truncated: false, limit: 500 };
    show();
    await loaded();
    expect(value("Databases")).toEqual(["0", "0%"]);
  });

  it("shows — everywhere, and no zero, while the inventory loads", async () => {
    api.listAssets.mockReturnValue(new Promise(() => {}));
    api.openPorts.mockReturnValue(new Promise(() => {}));
    show();
    expect(screen.getByText("Loading the asset inventory…")).toBeInTheDocument();
    expect(cards().every((c) => c.querySelector(".so-card-count")!.textContent === "—")).toBe(true);
    expect(screen.queryByText("0")).toBeNull();
    expect(panel("Asset Distribution").querySelector(".so-ring-value")).toHaveTextContent("—");
  });

  it("shows — and the failure when a page of the inventory fails, never a partial total", async () => {
    api.listAssets.mockImplementation((q: string) =>
      new URLSearchParams(q).get("before_id") ? Promise.reject(new ApiError(500, "internal", "boom")) : Promise.resolve({ assets: assetPages[0], address_presence: presence, next_before: ago(0), next_id: uuid(4) }));
    show();
    expect(await screen.findByText("Could not load the asset inventory, so its counts read —.")).toBeInTheDocument();
    expect(value("Total Assets")).toEqual(["—", "—"]);
    expect(value("IP Addresses")).toEqual(["—", "—"]);
    expect(within(panel("Recently Discovered Assets")).getByText("Could not load assets.")).toBeInTheDocument();
  });

  it("says why without asset.read, and reads nothing", async () => {
    session.permissions = ["finding.read"];
    show();
    expect(screen.getByText(/lacks the asset.read permission/)).toBeInTheDocument();
    expect(value("Total Assets")).toEqual(["—", "—"]);
    expect(api.listAssets).not.toHaveBeenCalled();
    await waitFor(() => expect(bodyRows("Recent Security Findings").length).toBeGreaterThan(0));
  });
});

describe("Security Overview recent panels", () => {
  it("lists at most five assets first seen in the period, newest first, without an all-blank Environment column", async () => {
    show();
    await loaded();
    const p = panel("Recently Discovered Assets");
    expect(within(p).getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Name", "Type", "IP / Endpoint", "First Seen", "Status"]);
    expect(bodyRows("Recently Discovered Assets").map((r) => within(r).getAllByRole("cell")[2].textContent)).toEqual(["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"]);
    const first = bodyRows("Recently Discovered Assets")[0];
    // A database host carries the Databases icon; status is never assumed.
    expect(first.querySelector("svg")).toHaveAttribute("data-icon", "database");
    expect(bodyRows("Recently Discovered Assets")[1].querySelector("svg")).toHaveAttribute("data-icon", "shapes");
    expect(within(first).getAllByRole("cell")[4]).toHaveTextContent("—");
    expect(within(first).getAllByRole("cell")[1]).toHaveTextContent("—");
  });

  it("shows the Environment column once any asset carries one", async () => {
    assetPages[1][0] = asset(5, 20, { environment: "staging" });
    show();
    await loaded();
    expect(within(panel("Recently Discovered Assets")).getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Name", "Type", "IP / Endpoint", "Environment", "First Seen", "Status"]);
  });

  it("lists at most five findings first seen in the period, newest first, with the module from the finding", async () => {
    show();
    await waitFor(() => expect(bodyRows("Recent Security Findings").length).toBe(5));
    const p = panel("Recent Security Findings");
    expect(within(p).getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Title", "Module", "Severity", "Asset", "Time"]);
    expect(bodyRows("Recent Security Findings").map((r) => within(r).getAllByRole("cell")[0].textContent)).toEqual(["rule-2", "rule-1", "rule-8", "rule-5", "rule-6"]);
    await waitFor(() => expect(within(bodyRows("Recent Security Findings")[0]).getAllByRole("cell")[1]).toHaveTextContent("network"));
    expect(bodyRows("Recent Security Findings").map((r) => within(r).getAllByRole("cell")[2].textContent)).toEqual(["Low", "Critical", "Medium", "High", "High"]);
  });

  it("applies the selected period to both panels and carries it to View All, leaving the inventory alone", async () => {
    const user = userEvent.setup();
    assetPages = [[asset(6, 30)], []];
    findings = [finding(3, 50, "medium")];
    show();
    await loaded();
    expect(await within(panel("Recent Security Findings")).findByText("No findings were first seen in the last 24 hours.")).toBeInTheDocument();
    expect(within(panel("Recently Discovered Assets")).getByText("No assets were first seen in the last 24 hours.")).toBeInTheDocument();
    await user.selectOptions(screen.getByLabelText("Time range"), "3d");
    expect(screen.getByTestId("where")).toHaveTextContent("/?range=3d");
    expect(within(panel("Recent Security Findings")).getByText("rule-3")).toBeInTheDocument();
    expect(bodyRows("Recently Discovered Assets")).toHaveLength(1);
    expect(value("Total Assets")).toEqual(["1", "100%"]);
    expect(within(panel("Recently Discovered Assets")).getByRole("link", { name: "View All →" })).toHaveAttribute("href", "/dashboard/recent-assets?range=3d");
    expect(within(panel("Recent Security Findings")).getByRole("link", { name: "View All →" })).toHaveAttribute("href", "/dashboard/recent-findings?range=3d");
  });

  it("says so when nothing was first seen in the period", async () => {
    assetPages = [[asset(7, 200)], []];
    findings = [finding(7, 2000)];
    show();
    expect(await within(panel("Recently Discovered Assets")).findByText("No assets were first seen in the last 24 hours.")).toBeInTheDocument();
    expect(await within(panel("Recent Security Findings")).findByText("No findings were first seen in the last 24 hours.")).toBeInTheDocument();
  });

  it("shows a findings failure as a failure", async () => {
    api.listFindings.mockRejectedValue(new ApiError(500, "internal", "boom"));
    show();
    expect(await within(panel("Recent Security Findings")).findByText("Could not load findings.")).toBeInTheDocument();
  });
});

describe("Security Overview navigation", () => {
  it("opens real listings for measured cards and the not-yet-integrated view for the rest", async () => {
    show();
    await loaded();
    expect(card("Total Assets")).toHaveAttribute("href", "/discover/discovery/asset-inventory");
    expect(card("Databases")).toHaveAttribute("href", "/discover/discovery/databases");
    expect(card("Servers")).toHaveAttribute("href", "/dashboard/categories/servers");
    await userEvent.setup().click(card("Kubernetes Clusters"));
    expect(screen.getByRole("heading", { name: "Kubernetes Clusters" })).toBeInTheDocument();
    expect(screen.getByText("Not yet integrated.")).toBeInTheDocument();
    // No figure of any kind on the page.
    expect(screen.getByRole("heading", { name: "Kubernetes Clusters" }).closest("section")!.textContent).not.toMatch(/\d/);
  });

  it("searches assets and findings from the header", async () => {
    const user = userEvent.setup();
    show();
    await user.type(screen.getByRole("searchbox"), "10.0.0.6{Enter}");
    expect(screen.getByTestId("where")).toHaveTextContent("/dashboard/search?q=10.0.0.6");
    await waitFor(() => expect(screen.getAllByText("10.0.0.6").length).toBeGreaterThan(0));
    expect(api.listAssets.mock.calls.some(([q]) => new URLSearchParams(q as string).get("q") === "10.0.0.6")).toBe(true);
  });

  it("View All lists every matching asset for the carried period", async () => {
    show("/dashboard/recent-assets?range=3d");
    await waitFor(() => expect(within(screen.getByRole("table")).getAllByRole("row").slice(1)).toHaveLength(6));
    expect(screen.getByRole("link", { name: "← Security Overview" })).toHaveAttribute("href", "/?range=3d");
  });
});
