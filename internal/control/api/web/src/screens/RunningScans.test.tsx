import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

const session = { user_id: "u-me", permissions: [] as string[] };
vi.mock("../lib/auth", () => ({ useAuth: () => ({ session }) }));
const api = vi.hoisted(() => ({
  listScans: vi.fn(), health: vi.fn(), listPolicies: vi.fn(), getScan: vi.fn(), scanResults: vi.fn(), cancelScan: vi.fn(),
}));
vi.mock("../lib/api", async (orig) => ({ ...(await orig<typeof import("../lib/api")>()), api }));

import { ApiError } from "../lib/api";
import { RunningScans } from "./RunningScans";

const S1 = "3f2a91c0-0000-4000-8000-000000000001";
const S2 = "8b11e7d4-0000-4000-8000-000000000002";
const S3 = "0d4cc2a8-0000-4000-8000-000000000003";
const P1 = "aaaaaaaa-0000-4000-8000-0000000000p1";
const P2 = "bbbbbbbb-0000-4000-8000-0000000000p2";
const scan = (id: string, extra = {}) => ({
  id, policy_id: P1, scan_type: "discovery", status: "pending", safety_mode: "safe", created_at: "2026-10-08T10:00:00Z", ...extra,
});
const byStatus: Record<string, object[]> = {
  pending: [scan(S3, { requested_by: undefined, policy_id: P2, scan_type: "rules" })],
  planning: [scan(S2, { status: "planning", requested_by: "1c9e4a77-0000-4000-8000-000000000000", safety_mode: "intrusive", scan_type: "fingerprint" })],
  running: [scan(S1, { status: "running", requested_by: "u-me", started_at: "2026-10-08T10:02:00Z" })],
};
const health = (blocked: object[] = []) => ({ blocked_scans: blocked, active_kills: [] });

function show() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}><MemoryRouter><RunningScans /></MemoryRouter></QueryClientProvider>);
}
const table = () => screen.getByRole("table");
const rowIds = () => within(table()).getAllByRole("row").slice(1).map((r) => within(r).getAllByRole("cell")[0].textContent);

beforeEach(() => {
  vi.clearAllMocks();
  session.permissions = ["scan.read", "scan.cancel", "policy.read"];
  api.listScans.mockImplementation((q: string) => Promise.resolve({ scans: byStatus[new URLSearchParams(q).get("status")!] ?? [] }));
  api.health.mockResolvedValue(health([{ id: S3, scan_type: "rules", status: "pending", policy_id: P2, engine: "rules", reason: "no capable scan point online" }]));
  api.listPolicies.mockResolvedValue({ policies: [{ id: P1, name: "lab-a", safety_mode: "safe", max_rate_pps: 100, max_concurrent_per_target: 1 }] });
  api.getScan.mockImplementation((id: string) => Promise.resolve(Object.values(byStatus).flat().find((s) => (s as { id: string }).id === id)));
  api.scanResults.mockResolvedValue({ scan_id: S1, ports: [{ address: "10.10.0.5", port: 22, protocol: "tcp", observed_at: "" }, { address: "10.10.0.5", port: 80, protocol: "tcp", observed_at: "" }], hosts: 1, truncated: false, limit: 2000, ephemeral: true });
});

describe("Running Scans", () => {
  it("asks for each in-flight status separately, never a multi-status filter", async () => {
    show();
    await screen.findByRole("table");
    const asked = api.listScans.mock.calls.map(([q]) => new URLSearchParams(q as string).getAll("status"));
    expect(asked).toEqual([["pending"], ["planning"], ["running"]]);
  });

  it("shows only real fields: counts, blocked from health, requester and policy labels", async () => {
    show();
    await screen.findByRole("table");
    const summary = screen.getByLabelText("Status summary");
    for (const [label, n] of [["Pending", "1"], ["Planning", "1"], ["Running", "1"], ["Blocked", "1"]]) {
      expect(within(within(summary).getByText(label).closest(".rs-tile") as HTMLElement).getByText(n)).toBeInTheDocument();
    }
    // Same request time, so the endpoint's own tie-break: id descending.
    expect(rowIds()).toEqual(["8b11e7d4", "3f2a91c0", "0d4cc2a8"]);
    const t = table();
    expect(within(t).getByText("You")).toBeInTheDocument();
    expect(within(t).getByText("system")).toBeInTheDocument();
    expect(within(t).getByText("1c9e4a77")).toBeInTheDocument();
    expect(within(t).getAllByText("lab-a").length).toBe(2);
    // A policy with no readable name falls back to its short id.
    expect(within(t).getByText("bbbbbbbb")).toBeInTheDocument();
    expect(within(t).getByText("Blocked")).toHaveAttribute("title", "no capable scan point online");
    expect(within(t).getByText(/^Running \d/)).toBeInTheDocument();
    expect(within(t).getAllByText(/^Waiting \d/).length).toBe(2);
    // Nothing that implies progress.
    expect(screen.queryByRole("progressbar")).toBeNull();
    expect(screen.queryByText(/%/)).toBeNull();
  });

  it("hides the Blocked tile when health did not answer", async () => {
    api.health.mockRejectedValue(new ApiError(403, "forbidden", "no"));
    show();
    await screen.findByRole("table");
    expect(within(screen.getByLabelText("Status summary")).queryByText("Blocked")).toBeNull();
  });

  it("filters by status, type, policy and requested-by-me", async () => {
    const user = userEvent.setup();
    show();
    await screen.findByRole("table");
    const filters = screen.getByRole("group", { name: "Filters" });
    await user.selectOptions(within(filters).getByLabelText("Status"), "running");
    expect(rowIds()).toEqual(["3f2a91c0"]);
    await user.selectOptions(within(filters).getByLabelText("Status"), "");
    await user.selectOptions(within(filters).getByLabelText("Type"), "fingerprint");
    expect(rowIds()).toEqual(["8b11e7d4"]);
    await user.selectOptions(within(filters).getByLabelText("Type"), "");
    await user.selectOptions(within(filters).getByLabelText("Policy"), P2);
    expect(rowIds()).toEqual(["0d4cc2a8"]);
    await user.selectOptions(within(filters).getByLabelText("Policy"), "");
    await user.click(within(filters).getByRole("button", { name: "Requested by me" }));
    expect(rowIds()).toEqual(["3f2a91c0"]);
    expect(screen.queryByRole("searchbox")).toBeNull();
  });

  it("View opens a drawer with the scan's facts and its observed results so far", async () => {
    const user = userEvent.setup();
    show();
    await screen.findByRole("table");
    await user.click(screen.getByRole("button", { name: "View scan 3f2a91c0" }));
    const drawer = screen.getByRole("dialog");
    expect(within(drawer).getByText(S1)).toBeInTheDocument();
    expect(within(drawer).getByText("Observed Results (So Far)")).toBeInTheDocument();
    const hosts = within(drawer).getByText("Hosts Observed").closest(".rs-tile") as HTMLElement;
    expect(await within(hosts).findByText("1")).toBeInTheDocument();
    expect(within(within(drawer).getByText("Open-Port Observations").closest(".rs-tile") as HTMLElement).getByText("2")).toBeInTheDocument();
    expect(within(drawer).getByText("Partial and current observations. Subject to change.")).toBeInTheDocument();
    expect(api.scanResults).toHaveBeenCalledWith(S1);
    await user.click(within(drawer).getByRole("button", { name: "Close" }));
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("Cancel requires a reason, calls the real endpoint, and reports success", async () => {
    const user = userEvent.setup();
    api.cancelScan.mockResolvedValue(scan(S1, { status: "cancelled" }));
    show();
    await screen.findByRole("table");
    await user.click(screen.getByRole("button", { name: "Cancel scan 3f2a91c0" }));
    const dialog = screen.getByRole("dialog");
    const submit = within(dialog).getByRole("button", { name: "Cancel scan" });
    expect(submit).toBeDisabled();
    await user.type(within(dialog).getByLabelText(/Reason/), "  wrong range  ");
    await user.click(submit);
    expect(api.cancelScan).toHaveBeenCalledWith(S1, "wrong range");
    expect(await screen.findByText("Scan 3f2a91c0 cancelled.")).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("Cancel shows the server's refusal instead of reporting success", async () => {
    const user = userEvent.setup();
    api.cancelScan.mockRejectedValue(new ApiError(409, "conflict", "That scan has already finished."));
    show();
    await screen.findByRole("table");
    await user.click(screen.getByRole("button", { name: "Cancel scan 3f2a91c0" }));
    const dialog = screen.getByRole("dialog");
    await user.type(within(dialog).getByLabelText(/Reason/), "stop");
    await user.click(within(dialog).getByRole("button", { name: "Cancel scan" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("That scan has already finished.");
    expect(screen.queryByText(/cancelled\.$/)).toBeNull();
  });

  it("disables Cancel without scan.cancel and says why", async () => {
    session.permissions = ["scan.read"];
    show();
    await screen.findByRole("table");
    const btn = screen.getByRole("button", { name: "Cancel scan 3f2a91c0" });
    expect(btn).toBeDisabled();
    expect(btn).toHaveAttribute("title", expect.stringContaining("scan.cancel"));
  });

  it("says so when nothing is in flight", async () => {
    api.listScans.mockResolvedValue({ scans: [] });
    show();
    expect(await screen.findByText("No scans are pending, planning or running.")).toBeInTheDocument();
  });
});

describe("Running Scans main table (unchanged by the drawer)", () => {
  it("keeps its ten columns, in order, and View and Cancel on every row", async () => {
    show();
    await screen.findByRole("table");
    expect(within(table()).getAllByRole("columnheader").map((h) => h.textContent)).toEqual([
      "Scan ID", "Type", "Status", "Safety Mode", "Policy", "Requested By", "Requested At", "Started At", "Time in Status", "Actions",
    ]);
    for (const row of within(table()).getAllByRole("row").slice(1)) {
      expect(within(row).getByRole("button", { name: /^View scan / })).toBeInTheDocument();
      expect(within(row).getByRole("button", { name: /^Cancel scan / })).toBeInTheDocument();
    }
  });
});

describe("Running Scans view drawer", () => {
  const open = async (short: string) => {
    const user = userEvent.setup();
    show();
    await screen.findByRole("table");
    await user.click(screen.getByRole("button", { name: `View scan ${short}` }));
    return screen.getByRole("dialog");
  };
  const tile = (drawer: HTMLElement, label: string) => within(drawer).getByText(label).closest(".rs-tile") as HTMLElement;
  const port = (address: string, p: number, observed_at = "2026-10-08T10:05:00Z") => ({ address, port: p, protocol: "tcp", observed_at });
  const results = (ports: object[], extra = {}) => ({ scan_id: S1, ports, hosts: new Set(ports.map((x) => (x as { address: string }).address)).size, truncated: false, limit: 2000, ephemeral: true, ...extra });

  it("leads with results: hosts, observations, ports grouped by host, latest observation", async () => {
    api.scanResults.mockResolvedValue(results([port("10.10.0.6", 443), port("10.10.0.5", 80, "2026-10-08T10:07:00Z"), port("10.10.0.5", 22)]));
    const drawer = await open("3f2a91c0");
    expect(await within(tile(drawer, "Hosts Observed")).findByText("2")).toBeInTheDocument();
    expect(within(tile(drawer, "Open-Port Observations")).getByText("3")).toBeInTheDocument();
    expect(within(drawer).queryByText(/Unique Open Ports/)).toBeNull();
    const hosts = within(drawer).getByRole("list", { name: "Ports by host" });
    expect(within(hosts).getAllByRole("listitem").map((li) => li.textContent)).toEqual(["10.10.0.6 → 443/TCP", "10.10.0.5 → 22/TCP, 80/TCP"]);
    expect(within(drawer).getByText(/Latest observation/).textContent).toContain(new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }).format(new Date("2026-10-08T10:07:00Z")));
    expect(within(drawer).getByRole("link", { name: "Open full results →" })).toHaveAttribute("href", `/scans/${S1}`);
  });

  it("marks both counts N+ when truncated and says only the first records are shown", async () => {
    api.scanResults.mockResolvedValue(results([port("10.10.0.5", 22), port("10.10.0.6", 22)], { truncated: true }));
    const drawer = await open("3f2a91c0");
    expect(await within(tile(drawer, "Hosts Observed")).findByText("2+")).toBeInTheDocument();
    expect(within(tile(drawer, "Open-Port Observations")).getByText("2+")).toBeInTheDocument();
    expect(within(drawer).getByText(/Showing only the first 2,000 records/)).toBeInTheDocument();
  });

  it("shows at most ten hosts and counts the omitted hosts, not rows", async () => {
    const rows = Array.from({ length: 12 }, (_, i) => [port(`10.10.0.${i + 1}`, 22), port(`10.10.0.${i + 1}`, 80)]).flat();
    api.scanResults.mockResolvedValue(results(rows));
    const drawer = await open("3f2a91c0");
    const hosts = await within(drawer).findByRole("list", { name: "Ports by host" });
    expect(within(hosts).getAllByRole("listitem")).toHaveLength(10);
    expect(within(drawer).getByText("+2 more hosts")).toBeInTheDocument();
  });

  it("never invents a latest time when no observation carries a valid one", async () => {
    api.scanResults.mockResolvedValue(results([port("10.10.0.5", 22, ""), port("10.10.0.5", 80, "not-a-date")]));
    const drawer = await open("3f2a91c0");
    await within(drawer).findByRole("list", { name: "Ports by host" });
    expect(within(drawer).queryByText(/Latest observation/)).toBeNull();
  });

  it("shows Loading… while results are pending", async () => {
    api.scanResults.mockReturnValue(new Promise(() => {}));
    const drawer = await open("3f2a91c0");
    expect(within(drawer).getByText("Loading…")).toBeInTheDocument();
    expect(within(drawer).queryByText("Hosts Observed")).toBeNull();
  });

  it("shows a failed request as a failure, never as zero", async () => {
    api.scanResults.mockRejectedValue(new ApiError(404, "not_found", "scan not found"));
    const drawer = await open("3f2a91c0");
    expect(await within(drawer).findByRole("alert")).toHaveTextContent("Could not load results: scan not found");
    expect(within(drawer).queryByText("Hosts Observed")).toBeNull();
    expect(within(drawer).queryByText("0")).toBeNull();
  });

  it("explains an empty in-flight discovery scan as not yet ingested", async () => {
    api.scanResults.mockResolvedValue(results([]));
    const drawer = await open("3f2a91c0");
    expect(await within(drawer).findByText("Nothing observed yet; results appear once accepted by ingest.")).toBeInTheDocument();
    expect(within(drawer).queryByText("Hosts Observed")).toBeNull();
  });

  it("explains an empty result for a scan type that records no port observations", async () => {
    api.scanResults.mockResolvedValue(results([]));
    const drawer = await open("8b11e7d4"); // fingerprint
    expect(await within(drawer).findByText("This scan type records no open-port observations.")).toBeInTheDocument();
  });

  it("explains an empty result for a discovery scan that has since finished", async () => {
    api.scanResults.mockResolvedValue(results([]));
    api.getScan.mockResolvedValue(scan(S1, { status: "completed", started_at: "2026-10-08T10:02:00Z", completed_at: "2026-10-08T10:30:00Z" }));
    const drawer = await open("3f2a91c0");
    expect(await within(drawer).findByText("No open-port observations remain (none recorded, or aged out).")).toBeInTheDocument();
  });

  it("shows the blocked reason and engine only for a scan health reports blocked", async () => {
    const blockedDrawer = await open("0d4cc2a8");
    const alert = within(blockedDrawer).getAllByRole("note").find((n) => n.textContent?.includes("Blocked"))!;
    expect(alert).toHaveTextContent("no capable scan point online");
    expect(alert).toHaveTextContent("engine rules");
  });

  it("does not show a blocked note for an unblocked scan", async () => {
    const drawer = await open("3f2a91c0");
    expect(within(drawer).queryByText(/engine/)).toBeNull();
  });

  it("shows policy limits with policy.read", async () => {
    const drawer = await open("3f2a91c0");
    expect(within(drawer).getByText("Policy limits")).toBeInTheDocument();
    expect(within(drawer).getByText("100 pps")).toBeInTheDocument();
    expect(within(drawer).getByText("Max concurrent per target").nextElementSibling).toHaveTextContent("1");
  });

  it("hides policy limits without policy.read", async () => {
    session.permissions = ["scan.read", "scan.cancel"];
    const drawer = await open("3f2a91c0");
    expect(within(drawer).queryByText("Policy limits")).toBeNull();
  });

  it("shows only kill switches that provably cover the scan: its own or tenant-wide, never zone-scoped", async () => {
    api.health.mockResolvedValue({ blocked_scans: [], active_kills: [
      { id: "k1", scope: "scan", scan_id: S1, reason: "stop this one", unacknowledged: 1, issued_at: "" },
      { id: "k2", scope: "scan", scan_id: S2, reason: "a different scan", unacknowledged: 0, issued_at: "" },
      { id: "k3", scope: "zone", zone_id: "z1", reason: "zone wide", unacknowledged: 0, issued_at: "" },
      { id: "k4", scope: "tenant", reason: "everything", unacknowledged: 0, issued_at: "" },
    ] });
    const drawer = await open("3f2a91c0");
    const notes = within(drawer).getAllByRole("note").map((n) => n.textContent);
    expect(notes.some((t) => t?.includes("stop this one") && t.includes("1 scan point not yet acknowledged"))).toBe(true);
    expect(notes.some((t) => t?.includes("everything"))).toBe(true);
    expect(notes.some((t) => t?.includes("a different scan"))).toBe(false);
    expect(notes.some((t) => t?.includes("zone wide"))).toBe(false);
  });

  it("drops the facts the table already shows, keeping full ids", async () => {
    const drawer = await open("3f2a91c0");
    const terms = within(drawer).getAllByRole("term").map((t) => t.textContent);
    for (const gone of ["Started At", "Type", "Status", "Safety Mode", "Waiting / Running"]) expect(terms).not.toContain(gone);
    expect(terms).toEqual(expect.arrayContaining(["Scan ID", "Policy", "Requested By", "Requested At"]));
    expect(within(drawer).getByText(S1)).toBeInTheDocument();
    expect(within(drawer).getByText(`· ${P1}`)).toBeInTheDocument();
    // Status, type and safety still lead the drawer, in its header line.
    const meta = within(drawer).getByLabelText("Scan summary");
    expect(meta).toHaveTextContent("Running");
    expect(meta).toHaveTextContent("discovery");
    expect(meta).toHaveTextContent("safe");
  });
});

