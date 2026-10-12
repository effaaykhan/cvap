import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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
// The page's clock, two hours after the fixtures were requested: every
// fixture is inside the 24-hour window unless a test moves it out.
const NOW = new Date("2026-10-08T12:00:00Z");
const DAY = 24 * 60 * 60 * 1000;
const at = (ms: number) => new Date(ms).toISOString();
let byStatus: Record<string, object[]>;
const fixtures = (): Record<string, object[]> => ({
  pending: [
    scan(S3, { requested_by: undefined, policy_id: P2, scan_type: "rules" }),
    scan(S2, { requested_by: "1c9e4a77-0000-4000-8000-000000000000", safety_mode: "intrusive", scan_type: "fingerprint" }),
  ],
  running: [scan(S1, { status: "running", requested_by: "u-me", started_at: "2026-10-08T10:02:00Z" })],
});
const health = (blocked: object[] = []) => ({ blocked_scans: blocked, active_kills: [] });

function show() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}><MemoryRouter><RunningScans /></MemoryRouter></QueryClientProvider>);
}
const table = () => screen.getByRole("table");
const scanRows = () => within(table()).getAllByRole("row").slice(1).filter((r) => !r.classList.contains("empty"));
const rowIds = () => scanRows().map((r) => within(r).getAllByRole("cell")[0].textContent);

beforeEach(() => {
  vi.clearAllMocks();
  // Only Date is faked: the window's reference time is deterministic while
  // React Query's and userEvent's timers stay real.
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW);
  byStatus = fixtures();
  session.permissions = ["scan.read", "scan.cancel", "policy.read"];
  api.listScans.mockImplementation((q: string) => Promise.resolve({ scans: byStatus[new URLSearchParams(q).get("status")!] ?? [] }));
  api.health.mockResolvedValue(health([{ id: S3, scan_type: "rules", status: "pending", policy_id: P2, engine: "rules", reason: "no capable scan point online" }]));
  api.listPolicies.mockResolvedValue({ policies: [{ id: P1, name: "lab-a", safety_mode: "safe", max_rate_pps: 100, max_concurrent_per_target: 1 }] });
  api.getScan.mockImplementation((id: string) => Promise.resolve(Object.values(byStatus).flat().find((s) => (s as { id: string }).id === id)));
  api.scanResults.mockResolvedValue({ scan_id: S1, ports: [{ address: "10.10.0.5", port: 22, protocol: "tcp", observed_at: "" }, { address: "10.10.0.5", port: 80, protocol: "tcp", observed_at: "" }], hosts: 1, truncated: false, limit: 2000, ephemeral: true });
});

afterEach(() => {
  vi.useRealTimers();
});

const summary = () => screen.getByLabelText("Status summary");
const tileCount = (label: string) => (within(summary()).getByText(label).closest(".rs-tile") as HTMLElement).querySelector(".rs-count")!.textContent;

describe("Running Scans", () => {
  it("asks for pending and running separately, never planning and never a multi-status filter", async () => {
    show();
    await screen.findByRole("table");
    const asked = api.listScans.mock.calls.map(([q]) => new URLSearchParams(q as string).getAll("status"));
    expect(asked).toEqual([["pending"], ["running"]]);
  });

  it("says which window it shows", async () => {
    show();
    await screen.findByRole("table");
    expect(screen.getByText("Showing scans requested in the last 24 hours.")).toBeInTheDocument();
  });

  it("shows only real fields: counts, blocked from health, requester and policy labels", async () => {
    show();
    await screen.findByRole("table");
    for (const [label, n] of [["Pending", "2"], ["Running", "1"], ["Blocked", "1"]]) expect(tileCount(label)).toBe(n);
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

  it("says so when nothing is in flight, and counts a genuine zero as 0", async () => {
    api.listScans.mockResolvedValue({ scans: [] });
    show();
    expect(await screen.findByText("No scans are pending or running in the last 24 hours.")).toBeInTheDocument();
    expect(tileCount("Pending")).toBe("0");
    expect(tileCount("Running")).toBe("0");
    expect(tileCount("Blocked")).toBe("0");
  });
});

describe("Running Scans 24-hour window", () => {
  const ids = () => (screen.queryByRole("table") ? rowIds() : []);
  const tiles = () => ({ pending: tileCount("Pending"), running: tileCount("Running") });

  it("keeps a scan requested exactly 24 hours ago, drops one a millisecond older, keeps a future one", async () => {
    const edge = NOW.getTime() - DAY;
    byStatus = {
      pending: [
        scan("aaaa0001-0000-4000-8000-000000000000", { created_at: at(edge) }),
        scan("aaaa0002-0000-4000-8000-000000000000", { created_at: at(edge - 1) }),
        // The same boundary instant written in another zone is the same instant.
        scan("aaaa0003-0000-4000-8000-000000000000", { created_at: "2026-10-07T17:30:00+05:30" }),
        // Ahead of the browser's clock (skew with Core): in, not hidden.
        scan("aaaa0004-0000-4000-8000-000000000000", { created_at: at(NOW.getTime() + 60 * 60 * 1000) }),
      ],
      running: [
        scan("bbbb0001-0000-4000-8000-000000000000", { status: "running", created_at: at(edge + 1), started_at: at(edge + 1) }),
        scan("bbbb0002-0000-4000-8000-000000000000", { status: "running", created_at: "2026-10-05T09:00:00Z", started_at: "2026-10-05T09:01:00Z" }),
      ],
    };
    show();
    await screen.findByRole("table");
    expect(ids().sort()).toEqual(["aaaa0001", "aaaa0003", "aaaa0004", "bbbb0001"]);
    expect(tiles()).toEqual({ pending: "3", running: "1" });
  });

  it("shows the empty state, and zero counts, when every in-flight scan is older than 24 hours", async () => {
    byStatus = {
      pending: [scan(S3, { created_at: "2026-10-01T10:00:00Z" })],
      running: [scan(S1, { status: "running", created_at: "2026-09-25T10:00:00Z", started_at: "2026-09-25T10:01:00Z" })],
    };
    show();
    expect(await screen.findByText("No scans are pending or running in the last 24 hours.")).toBeInTheDocument();
    expect(tiles()).toEqual({ pending: "0", running: "0" });
    // The blocked scan is outside the window, so it is not counted either.
    expect(tileCount("Blocked")).toBe("0");
  });

  it("never shows or counts planning, even if a read returned it", async () => {
    byStatus.pending = [...byStatus.pending, scan("cccc0001-0000-4000-8000-000000000000", { status: "planning" })];
    byStatus.running = [...byStatus.running, scan("cccc0002-0000-4000-8000-000000000000", { status: "planning" })];
    show();
    await screen.findByRole("table");
    expect(ids()).not.toContain("cccc0001");
    expect(ids()).not.toContain("cccc0002");
    expect(tiles()).toEqual({ pending: "2", running: "1" });
    expect(screen.queryByText(/planning/i)).toBeNull();
    const status = within(screen.getByRole("group", { name: "Filters" })).getByLabelText("Status");
    expect(within(status).getAllByRole("option").map((o) => o.textContent)).toEqual(["All", "Pending", "Running"]);
  });

  it("counts exactly the rows the table shows, per status", async () => {
    const user = userEvent.setup();
    byStatus.pending = [...byStatus.pending, scan("dddd0001-0000-4000-8000-000000000000", { created_at: "2026-10-06T10:00:00Z" })];
    show();
    await screen.findByRole("table");
    expect(rowIds().length).toBe(Number(tileCount("Pending")) + Number(tileCount("Running")));
    const filter = within(screen.getByRole("group", { name: "Filters" })).getByLabelText("Status");
    await user.selectOptions(filter, "pending");
    expect(rowIds().length).toBe(Number(tileCount("Pending")));
    await user.selectOptions(filter, "running");
    expect(rowIds().length).toBe(Number(tileCount("Running")));
  });

  it("marks a count N+ only when a further page could still hold scans inside the window", async () => {
    byStatus = {
      pending: [scan(S3), scan(S2)],
      running: [scan(S1, { status: "running" }), scan("eeee0001-0000-4000-8000-000000000000", { status: "running", created_at: "2026-10-01T00:00:00Z" })],
    };
    api.listScans.mockImplementation((q: string) => Promise.resolve({ scans: byStatus[new URLSearchParams(q).get("status")!], next_before: "c", next_id: "x" }));
    show();
    await screen.findByRole("table");
    // Pending's page ends inside the window: more may follow. Running's page
    // already reached an older scan, so later pages are older still.
    expect(tiles()).toEqual({ pending: "2+", running: "1" });
  });

  it("judges the window again, at a fresh time, on the next refresh", async () => {
    const user = userEvent.setup();
    show();
    await screen.findByRole("table");
    expect(rowIds()).toContain("0d4cc2a8");
    // 22h later every fixture is 24h + 1ms old except S2, re-requested.
    vi.setSystemTime(NOW.getTime() + 22 * 60 * 60 * 1000 + 1);
    byStatus.pending = [scan(S3), scan(S2, { created_at: at(NOW.getTime() + 60 * 60 * 1000) })];
    await user.click(screen.getByRole("button", { name: "Refresh" }));
    await waitFor(() => expect(rowIds()).toEqual(["8b11e7d4"]));
    expect(tiles()).toEqual({ pending: "1", running: "0" });
  });

  it("shows Loading… and no counts, no zero and no empty state while the reads are pending", async () => {
    api.listScans.mockReturnValue(new Promise(() => {}));
    show();
    expect(await screen.findByText("Loading…")).toBeInTheDocument();
    expect(tiles()).toEqual({ pending: "—", running: "—" });
    expect(within(summary()).queryByText("Blocked")).toBeNull();
    expect(screen.queryByText(/No scans are pending/)).toBeNull();
    expect(screen.queryByText("0")).toBeNull();
  });

  it("shows a failed read as an error, never as zero or as nothing in flight", async () => {
    api.listScans.mockRejectedValue(new ApiError(500, "internal", "boom"));
    show();
    expect(await screen.findByText(/Could not load every in-flight status/)).toBeInTheDocument();
    expect(tiles()).toEqual({ pending: "—", running: "—" });
    expect(within(summary()).queryByText("Blocked")).toBeNull();
    expect(screen.queryByText(/No scans are pending/)).toBeNull();
    expect(screen.queryByText("0")).toBeNull();
  });

  it("stops counting a read that fails on refresh, rather than showing its last count", async () => {
    const user = userEvent.setup();
    show();
    await screen.findByRole("table");
    expect(tiles()).toEqual({ pending: "2", running: "1" });
    api.listScans.mockImplementation((q: string) =>
      new URLSearchParams(q).get("status") === "pending" ? Promise.reject(new ApiError(500, "internal", "boom")) : Promise.resolve({ scans: byStatus.running }));
    await user.click(screen.getByRole("button", { name: "Refresh" }));
    expect(await screen.findByText(/Could not load every in-flight status/)).toBeInTheDocument();
    expect(tiles()).toEqual({ pending: "—", running: "1" });
    expect(within(summary()).queryByText("Blocked")).toBeNull();
  });

  it("keeps the permission message for a 403", async () => {
    api.listScans.mockRejectedValue(new ApiError(403, "forbidden", "no"));
    show();
    expect(await screen.findByText("This account cannot read scans (it lacks the scan.read permission).")).toBeInTheDocument();
    expect(screen.queryByText(/No scans are pending/)).toBeNull();
  });

  it("with one read failed, counts only the one that answered and still shows its rows", async () => {
    api.listScans.mockImplementation((q: string) =>
      new URLSearchParams(q).get("status") === "pending" ? Promise.reject(new ApiError(500, "internal", "boom")) : Promise.resolve({ scans: byStatus.running }));
    show();
    await screen.findByRole("table");
    expect(tiles()).toEqual({ pending: "—", running: "1" });
    expect(rowIds()).toEqual(["3f2a91c0"]);
    expect(within(summary()).queryByText("Blocked")).toBeNull();
    expect(screen.getByText(/Could not load every in-flight status/)).toBeInTheDocument();
  });
});

describe("Running Scans main table (unchanged by the drawer)", () => {
  const COLUMNS = ["Scan ID", "Type", "Status", "Safety Mode", "Policy", "Requested By", "Requested At", "Started At", "Time in Status", "Actions"];
  const headers = () => within(table()).getAllByRole("columnheader").map((h) => h.textContent);
  const bodyRows = () => within(table()).getAllByRole("row").slice(1);
  // The empty table: every column header, and one row whose single cell spans them all.
  const expectEmptyTable = (message: string) => {
    expect(headers()).toEqual(COLUMNS);
    const rows = bodyRows();
    expect(rows).toHaveLength(1);
    const cells = within(rows[0]).getAllByRole("cell");
    expect(cells).toHaveLength(1);
    expect(cells[0]).toHaveAttribute("colspan", String(COLUMNS.length));
    expect(cells[0]).toHaveTextContent(message);
    expect(within(table()).queryByRole("button")).toBeNull();
  };

  it("keeps its ten columns, in order, and View and Cancel on every row", async () => {
    show();
    await screen.findByRole("table");
    expect(headers()).toEqual(COLUMNS);
    expect(bodyRows()).toHaveLength(3);
    for (const row of bodyRows()) {
      expect(within(row).getAllByRole("cell")).toHaveLength(COLUMNS.length);
      expect(within(row).getByRole("button", { name: /^View scan / })).toBeInTheDocument();
      expect(within(row).getByRole("button", { name: /^Cancel scan / })).toBeInTheDocument();
    }
    expect(within(table()).queryByText(/No scans are pending|No in-flight scans match/)).toBeNull();
  });

  it("keeps every column header with zero scans, the empty state inside the table", async () => {
    api.listScans.mockResolvedValue({ scans: [] });
    show();
    await screen.findByRole("table");
    expectEmptyTable("No scans are pending or running in the last 24 hours.");
  });

  it("keeps every column header when every scan is older than 24 hours", async () => {
    byStatus = {
      pending: [scan(S3, { created_at: "2026-10-01T10:00:00Z" })],
      running: [scan(S1, { status: "running", created_at: "2026-09-25T10:00:00Z", started_at: "2026-09-25T10:01:00Z" })],
    };
    show();
    await screen.findByRole("table");
    expectEmptyTable("No scans are pending or running in the last 24 hours.");
  });

  it("keeps every column header when the filters match nothing, and brings the rows back", async () => {
    const user = userEvent.setup();
    show();
    await screen.findByRole("table");
    const filters = screen.getByRole("group", { name: "Filters" });
    await user.selectOptions(within(filters).getByLabelText("Type"), "fingerprint");
    await user.selectOptions(within(filters).getByLabelText("Status"), "running");
    expectEmptyTable("No in-flight scans match these filters.");
    await user.selectOptions(within(filters).getByLabelText("Status"), "");
    await user.selectOptions(within(filters).getByLabelText("Type"), "");
    expect(rowIds()).toEqual(["8b11e7d4", "3f2a91c0", "0d4cc2a8"]);
  });

  it("keeps the header, with no empty-state row, when the reads failed", async () => {
    api.listScans.mockRejectedValue(new ApiError(500, "internal", "boom"));
    show();
    await screen.findByText(/Could not load every in-flight status/);
    expect(headers()).toEqual(COLUMNS);
    expect(bodyRows()).toHaveLength(0);
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

