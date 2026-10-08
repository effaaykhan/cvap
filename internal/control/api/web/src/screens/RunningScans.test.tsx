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
    expect(within(within(drawer).getByText("Open Ports Observed").closest(".rs-tile") as HTMLElement).getByText("2")).toBeInTheDocument();
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
