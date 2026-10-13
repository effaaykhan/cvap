import { describe, expect, it, vi } from "vitest";
import {
  allAssets, allFindings, CATEGORIES, categoryByKey, databaseHosts, distribution, fmtShare, inRange, matchFinding,
  measure, MAX_PAGES, newestBy, rangeFor, RANGES, share,
} from "./dashboard";
import type { AssetSummary, FindingSummary, OpenPorts } from "./api";

const NOW = new Date("2026-10-13T12:00:00Z").getTime();
const asset = (id: string, extra: Partial<AssetSummary> = {}): AssetSummary => ({
  id, hostname: "", os_family: "", device_type: "", criticality: "unknown", environment: "", fragile: false,
  first_seen: "2026-10-13T10:00:00Z", last_seen: "2026-10-13T11:00:00Z", open_findings: 0, kev_findings: 0, advisory_status: "no_release", ...extra,
} as AssetSummary);
const ports = (rows: [string, string][], truncated = false): OpenPorts => ({
  ports: rows.map(([asset_id, service]) => ({ asset_id, address: "", hostname: "", port: 1, protocol: "tcp", service, product: "", identified: true, last_seen: "" })),
  truncated, limit: 500,
} as OpenPorts);

describe("Security Overview ranges", () => {
  it("offers the seven periods in order, defaulting to the last 24 hours", () => {
    expect(RANGES.map((r) => r.label)).toEqual(["Last 24 Hours", "Last 3 Days", "Last 7 Days", "Last 15 Days", "Last 30 Days", "Last 60 Days", "Last 90 Days"]);
    expect(rangeFor(null).label).toBe("Last 24 Hours");
    expect(rangeFor("nonsense").label).toBe("Last 24 Hours");
    expect(rangeFor("15d").days).toBe(15);
  });

  it("keeps the exact boundary, drops a millisecond older, keeps a future time, drops an unparseable one", () => {
    expect(inRange("2026-10-12T12:00:00Z", 1, NOW)).toBe(true);
    expect(inRange("2026-10-12T11:59:59.999Z", 1, NOW)).toBe(false);
    expect(inRange("2026-10-12T17:30:00+05:30", 1, NOW)).toBe(true);
    expect(inRange("2026-10-13T13:00:00Z", 1, NOW)).toBe(true);
    expect(inRange("2026-10-10T12:00:00Z", 3, NOW)).toBe(true);
    expect(inRange("bad", 90, NOW)).toBe(false);
    expect(inRange(undefined, 90, NOW)).toBe(false);
  });

  it("orders newest first with a stable tie-break", () => {
    const rows = [asset("a", { first_seen: "2026-10-01T00:00:00Z" }), asset("c"), asset("b")];
    expect(newestBy(rows, (r) => r.first_seen).map((r) => r.id)).toEqual(["c", "b", "a"]);
  });
});

describe("Security Overview categories", () => {
  it("holds the twelve categories in the required order with their colours and icons", () => {
    expect(CATEGORIES.map((c) => c.label)).toEqual([
      "Total Assets", "IP Addresses", "Servers", "Laptops", "APIs", "Web Applications",
      "Docker Containers", "Kubernetes Clusters", "Databases", "Cloud Assets", "Network Devices", "Other Assets",
    ]);
    expect(CATEGORIES.map((c) => c.color)).toEqual([
      "#3B82F6", "#3B82F6", "#8B5CF6", "#10B981", "#F97316", "#10B981", "#3B82F6", "#8B5CF6", "#F43F5E", "#F59E0B", "#06B6D4", "#94A3B8",
    ]);
    expect(CATEGORIES.every((c) => !!c.icon)).toBe(true);
    // Only what Core measures leads somewhere real; everything else explains its gap.
    expect(CATEGORIES.filter((c) => c.to).map((c) => c.key)).toEqual(["total", "ip", "databases"]);
    expect(CATEGORIES.filter((c) => !c.to).every((c) => !!c.gap)).toBe(true);
  });

  it("measures total, addresses and database hosts; every other category stays unmeasured", () => {
    const ms = measure({ assets: [asset("a"), asset("b"), asset("c")], addresses: 5, openPorts: ports([["a", "mysql"], ["a", "postgresql"], ["b", "ssh"]]) });
    expect(ms.total.count).toBe(3);
    expect(ms.ip.count).toBe(5);
    // One host with two engines is one database host.
    expect(ms.databases.count).toBe(1);
    for (const k of ["servers", "laptops", "apis", "webapps", "docker", "k8s", "cloud", "network", "other"] as const) expect(ms[k].count).toBeNull();
  });

  it("counts nothing that has not loaded, never zero", () => {
    const ms = measure({});
    expect([ms.total.count, ms.ip.count, ms.databases.count]).toEqual([null, null, null]);
  });

  it("reads database hosts as unknown past the open-port cap, keeping only a lower-bound hint", () => {
    const m = databaseHosts(ports([["a", "mysql"]], true));
    expect(m.count).toBeNull();
    expect(m.atLeast).toBe(1);
    expect(m.note).toContain("500");
    expect(databaseHosts(ports([], false)).count).toBe(0);
  });

  it("computes share over the whole inventory, only for slices, and never forces 100%", () => {
    const total = categoryByKey("total")!, ip = categoryByKey("ip")!, db = categoryByKey("databases")!;
    expect(share(total, { count: 526 }, 526)).toBe(100);
    expect(share(ip, { count: 14 }, 526)).toBeNull();
    expect(share(db, { count: 1 }, 526)).toBeCloseTo(0.19, 2);
    expect(share(db, { count: null }, 526)).toBeNull();
    expect(share(db, { count: 1 }, null)).toBeNull();
    expect(share(db, { count: 0 }, 0)).toBeNull();
    expect([fmtShare(null), fmtShare(0), fmtShare(100), fmtShare(0.19), fmtShare(37.6)]).toEqual(["—", "0%", "100%", "0.2%", "38%"]);
  });

  it("draws only measured slices, and an Unclassified remainder only when every slice was measured", () => {
    const ms = measure({ assets: [asset("a"), asset("b")], openPorts: ports([["a", "mysql"]]) });
    expect(distribution(ms, 2)).toEqual([{ key: "databases", label: "Databases", color: "#F43F5E", value: 1 }]);
    expect(distribution(ms, null)).toEqual([]);
    const all = Object.fromEntries(Object.entries(ms).map(([k, m]) => [k, k === "databases" ? m : { count: 0 }])) as typeof ms;
    expect(distribution(all, 2).map((s) => [s.key, s.value])).toEqual([["databases", 1], ["unclassified", 1]]);
  });
});

describe("Security Overview paging", () => {
  it("reads every asset page and takes the address total from the first", async () => {
    const list = vi.fn()
      .mockResolvedValueOnce({ assets: [asset("a"), asset("b")], next_before: "2026-10-13T11:00:00Z", next_id: "b", address_presence: { total: 7 } })
      .mockResolvedValueOnce({ assets: [asset("c")] });
    const r = await allAssets(list, 2);
    expect(r.assets.map((a) => a.id)).toEqual(["a", "b", "c"]);
    expect(r.addresses).toBe(7);
    expect(list.mock.calls.map(([q]) => q)).toEqual(["?limit=2", "?limit=2&before=2026-10-13T11%3A00%3A00Z&before_id=b"]);
  });

  it("fails the whole read when a page fails, rather than returning a partial total", async () => {
    const list = vi.fn().mockResolvedValueOnce({ assets: [asset("a")], next_before: "t", next_id: "a" }).mockRejectedValueOnce(new Error("boom"));
    await expect(allAssets(list)).rejects.toThrow("boom");
  });

  it("stops at the page bound with an error instead of looping or truncating", async () => {
    const list = vi.fn().mockResolvedValue({ assets: [asset("a")], next_before: "t", next_id: "a" });
    await expect(allAssets(list, 1)).rejects.toThrow(/cannot count them exactly/);
    expect(list).toHaveBeenCalledTimes(MAX_PAGES);
  });

  it("reads every finding page by the priority cursor", async () => {
    const f = (id: string) => ({ id } as FindingSummary);
    const list = vi.fn().mockResolvedValueOnce({ findings: [f("x")], next_score: "9", next_id: "x" }).mockResolvedValueOnce({ findings: [f("y")] });
    expect((await allFindings(list, 1)).map((x) => x.id)).toEqual(["x", "y"]);
    expect(list.mock.calls[1][0]).toBe("?limit=1&before_score=9&before_id=x");
  });

  it("matches a finding by rule, CVE, category or asset, case-insensitively", () => {
    const f = { id: "1", rule: "plaintext-telnet", cve: "CVE-2024-1", category: "exposure", asset_hostname: "db01", asset_id: "u1" } as FindingSummary;
    expect(["TELNET", "cve-2024", "expos", "DB01"].every((q) => matchFinding(f, q))).toBe(true);
    expect(matchFinding(f, "nginx")).toBe(false);
    expect(matchFinding(f, "  ")).toBe(false);
  });
});
