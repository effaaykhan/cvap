import { render, screen, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

const session = { permissions: [] as string[] };
vi.mock("../lib/auth", () => ({ useAuth: () => ({ session }) }));
const api = vi.hoisted(() => ({
  listAssets: vi.fn(), getAsset: vi.fn(), openPorts: vi.fn(), listScans: vi.fn(), scanResults: vi.fn(),
  listZones: vi.fn(), listScanPoints: vi.fn(), identityQueue: vi.fn(), health: vi.fn(),
}));
vi.mock("../lib/api", async (orig) => ({ ...(await orig<typeof import("../lib/api")>()), api }));

import { AssetInventory } from "./AssetInventory";
import { NetworkDiscovery } from "./NetworkDiscovery";
import { WebDiscovery } from "./WebDiscovery";
import { Databases } from "./Databases";
import { UnknownAssets } from "./UnknownAssets";

function show(node: React.ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}><MemoryRouter>{node}</MemoryRouter></QueryClientProvider>);
}

const A1 = "11111111-aaaa-4aaa-8aaa-000000000001";
const A2 = "22222222-bbbb-4bbb-8bbb-000000000002";
const noPresence = { present: 0, responder: 0, unknown: 0, total: 0, statement: "No addresses have been observed yet." };
const asset = (id: string, extra = {}) => ({
  id, hostname: "", address: undefined, os_family: "", device_type: "", environment: "", criticality: "unknown",
  first_seen: "2026-09-23T10:00:00Z", last_seen: "2026-09-25T10:00:00Z", fragile: false, open_findings: 0, kev_findings: 0,
  advisory_status: "no_release", ...extra,
});
const detail = (id: string, extra = {}) => ({
  ...asset(id), addresses: [], services: [], identity_keys: [], identity_keys_total: 0, ...extra,
});
const port = (asset_id: string, port: number, extra = {}) => ({
  asset_id, port, protocol: "tcp", identified: false, last_seen: "2026-09-25T10:00:00Z", ...extra,
});

beforeEach(() => {
  vi.clearAllMocks();
  session.permissions = ["asset.read", "scan.read", "zone.read", "scan_point.read"];
  api.openPorts.mockResolvedValue({ ports: [], truncated: false, limit: 500 });
});

describe("Asset Inventory", () => {
  it("shows the inventory from real fields and says what is not collected", async () => {
    api.listAssets.mockResolvedValue({ assets: [asset(A1), asset(A2, { open_findings: 2 })], address_presence: noPresence });
    api.getAsset.mockImplementation((id: string) => Promise.resolve(id === A1
      ? detail(A1, { distro_family: "ubuntu", os_confidence: 0.6, services: [{ port: 22, protocol: "tcp", service: "ssh", method: "banner", last_seen: "" }] })
      : detail(A2)));
    show(<AssetInventory />);
    expect(await screen.findByText("ubuntu")).toBeInTheDocument();
    expect(await screen.findByText("not attributed")).toBeInTheDocument();
    expect(screen.getByText("1 recognised")).toBeInTheDocument();
    // No current address: the id is the label, and the page says why.
    expect(screen.getByText("No asset holds a current address, so assets are listed by id.")).toBeInTheDocument();
    expect(screen.queryByText("· no current address")).not.toBeInTheDocument();
    expect(screen.getByText("no asset currently holds a live address")).toBeInTheDocument();
    // Inventory, not posture: no hostname/vendor/device columns.
    const head = screen.getAllByRole("columnheader").map((h) => h.textContent);
    expect(head).not.toContain("Hostname");
    expect(head).not.toContain("Vendor");
    expect(head).toContain("Operating system");
    expect(screen.getByText(/Not collected today, so not shown/)).toBeInTheDocument();
  });
});

describe("Network Discovery", () => {
  it("lists only discovery scans with hosts and ports from their results", async () => {
    api.listScans.mockResolvedValue({ scans: [
      { id: "d1000000-0000-4000-8000-000000000000", scan_type: "discovery", status: "completed", safety_mode: "safe", policy_id: "p", created_at: "2026-09-25T07:44:54Z", started_at: "2026-09-25T07:45:02Z", completed_at: "2026-09-25T13:27:48Z" },
      { id: "f1000000-0000-4000-8000-000000000000", scan_type: "fingerprint", status: "completed", safety_mode: "safe", policy_id: "p", created_at: "2026-09-25T06:00:00Z" },
    ] });
    api.scanResults.mockResolvedValue({ scan_id: "d1", hosts: 2, ports: [
      { address: "10.0.0.1", port: 445, protocol: "tcp", observed_at: "" }, { address: "10.0.0.2", port: 445, protocol: "tcp", observed_at: "" },
      { address: "10.0.0.2", port: 22, protocol: "tcp", observed_at: "" },
    ], truncated: false, limit: 2000, ephemeral: true });
    api.listZones.mockResolvedValue({ zones: [{ id: "z", name: "internal", type: "internal", trust_level: 50 }] });
    api.listScanPoints.mockResolvedValue({ scan_points: [{ id: "sp", hostname: "sp-1", zone_id: "z", health: "healthy", capabilities: ["discovery"], status: "online", agent_version: "", protocol_version: "", leases_held: 0 }] });
    show(<NetworkDiscovery />);
    const table = (await screen.findByText("Discovery scans", { selector: ".card-head .lbl" })).closest(".card") as HTMLElement;
    expect(await within(table).findByText("d1000000")).toBeInTheDocument();
    expect(within(table).queryByText("f1000000")).not.toBeInTheDocument();
    expect(within(table).getByText("5h 43m")).toBeInTheDocument();
    expect(screen.getByText("445/tcp")).toBeInTheDocument();
    expect(screen.getByText(/resolves no names and sends no ICMP or ARP/)).toBeInTheDocument();
  });
});

describe("Web & API Discovery", () => {
  it("labels web-port rows by state and never as web servers", async () => {
    api.openPorts.mockResolvedValue({ ports: [port(A1, 80), port(A1, 22, { identified: true, service: "ssh" })], truncated: false, limit: 500 });
    show(<WebDiscovery />);
    const table = (await screen.findByText("Web probe ports", { selector: ".lbl" })).closest(".card") as HTMLElement;
    expect(await within(table).findByText("80/tcp")).toBeInTheDocument();
    expect(within(table).getByText("open, unidentified")).toBeInTheDocument();
    expect(within(table).queryByText("22/tcp")).not.toBeInTheDocument();
    expect(screen.getAllByText("not available").length).toBeGreaterThan(0);
    expect(screen.getAllByText("URL and path discovery").length).toBeGreaterThan(0);
  });
});

describe("Databases", () => {
  it("shows identified engines with versions from the asset record, and engine ports apart", async () => {
    api.openPorts.mockResolvedValue({ ports: [
      port(A1, 3306, { identified: true, service: "mysql", product: "MySQL" }),
      port(A2, 5432),
      port(A2, 1521),
    ], truncated: false, limit: 500 });
    api.getAsset.mockResolvedValue(detail(A1, { services: [{ port: 3306, protocol: "tcp", service: "mysql", product: "MySQL", version: "8.0.36", version_confidence: 0.95, method: "banner", last_seen: "" }] }));
    show(<Databases />);
    expect(await screen.findByText("8.0.36")).toBeInTheDocument();
    const unconfirmed = screen.getByText("Open on a database port, not identified", { selector: ".lbl" }).closest(".card") as HTMLElement;
    expect(within(unconfirmed).getByText("5432/tcp")).toBeInTheDocument();
    // Oracle's port is not claimed: no rule identifies Oracle.
    expect(screen.queryByText("1521/tcp")).not.toBeInTheDocument();
  });
});

describe("Unknown Assets", () => {
  it("keeps presence, unidentified ports and contested identity apart", async () => {
    api.listAssets.mockResolvedValue({ assets: [], address_presence: noPresence });
    api.openPorts.mockResolvedValue({ ports: [port(A1, 5060), port(A2, 22, { identified: true, service: "ssh" })], truncated: true, limit: 500 });
    api.identityQueue.mockResolvedValue({ addresses_total: 1, groups: [{ address: "10.0.0.9", reason: "ssh host key changed", items_total: 2, candidates: [A1], last_seen: "2026-09-25T10:00:00Z", first_seen: "", items: [], keys: [], held: [], ambiguous: [], ambiguous_total: 0, keys_total: 1 }] });
    api.health.mockResolvedValue({ unresolved_observations: 3, resolution_queue_pending: 2, contested_addresses: 1, blocked_scans: [], active_kills: [] });
    show(<UnknownAssets />);
    expect(await screen.findByText("10.0.0.9")).toBeInTheDocument();
    // Total 0: the server's "never observed" sentence is not shown as a verdict.
    expect(screen.getByText(/No asset currently holds a live address, so there is no presence verdict/)).toBeInTheDocument();
    expect(screen.queryByText("No addresses have been observed yet.")).not.toBeInTheDocument();
    const table = screen.getByText("Assets with no recognised service", { selector: ".lbl" }).closest(".card") as HTMLElement;
    expect(within(table).getByText("5060/tcp")).toBeInTheDocument();
    expect(within(table).queryByText("22/tcp")).not.toBeInTheDocument();
    expect(screen.getByText(/Built from the 500 most recently seen open ports/)).toBeInTheDocument();
  });
});
