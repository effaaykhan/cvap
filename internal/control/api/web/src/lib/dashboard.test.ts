import { describe, expect, it, vi } from "vitest";
import {
  allAssets, allFindings, arcs, assetKind, CATEGORIES, categoryByKey, databaseHosts, distribution, fmtShare, inRange,
  matchFinding, measure, MAX_PAGES, newestBy, rangeFor, RANGES, share,
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
  it("holds the eleven categories in the required order, Other Assets removed, each with its own colour and icon", () => {
    expect(CATEGORIES.map((c) => c.label)).toEqual([
      "Total Assets", "IP Addresses", "Servers", "Laptops", "APIs", "Web Applications",
      "Docker Containers", "Kubernetes Clusters", "Databases", "Cloud Assets", "Network Devices",
    ]);
    expect(categoryByKey("other")).toBeUndefined();
    expect(new Set(CATEGORIES.map((c) => c.color)).size).toBe(11);
    expect(new Set(CATEGORIES.map((c) => c.icon)).size).toBe(11);
    expect(CATEGORIES.every((c) => /^#[0-9A-F]{6}$/.test(c.color) && /^#[0-9A-F]{6}$/.test(c.dark) && c.dark !== c.color)).toBe(true);
    // Only what Core measures leads somewhere real; everything else explains its gap.
    expect(CATEGORIES.filter((c) => c.to).map((c) => c.key)).toEqual(["total", "ip", "databases"]);
    expect(CATEGORIES.filter((c) => !c.to).every((c) => !!c.gap)).toBe(true);
  });

  it("keeps a white glyph at 3:1 or better on every tile's darker shade", () => {
    const lum = (hex: string) => {
      const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
      return 0.2126 * r + 0.7152 * g + 0.0722 * b;
    };
    for (const c of CATEGORIES) expect((1.05 / (lum(c.dark) + 0.05))).toBeGreaterThanOrEqual(3);
  });

  it("measures total, addresses and database hosts; every other category stays unmeasured", () => {
    const ms = measure({ assets: [asset("a", { address: "10.0.0.1" }), asset("b"), asset("c")], addresses: 5, openPorts: ports([["a", "mysql"], ["a", "postgresql"], ["b", "ssh"]]) });
    expect(ms.total.count).toBe(3);
    // IP Addresses counts addresses; the assets holding one are what its share is taken from.
    expect(ms.ip.count).toBe(5);
    expect(ms.ip.assets).toBe(1);
    expect(ms.ip.note).toContain("held by 1 of the 3 assets");
    // One host with two engines is one database host.
    expect(ms.databases.count).toBe(1);
    for (const k of ["servers", "laptops", "apis", "webapps", "docker", "k8s", "cloud", "network"] as const) expect(ms[k].count).toBeNull();
  });

  it("counts nothing that has not loaded, never zero", () => {
    const ms = measure({});
    expect([ms.total.count, ms.ip.count, ms.ip.assets, ms.databases.count]).toEqual([null, null, null, null]);
  });

  it("reads database hosts as unknown past the open-port cap, keeping only a lower-bound hint", () => {
    const m = databaseHosts(ports([["a", "mysql"]], true));
    expect(m.count).toBeNull();
    expect(m.atLeast).toBe(1);
    expect(m.note).toContain("500");
    expect(databaseHosts(ports([], false))).toEqual({ count: 0, assets: 0 });
  });

  it("takes every share over the inventory: Total has none, IP is the addressed assets, 526 and 14 are never added", () => {
    const total = categoryByKey("total")!, ip = categoryByKey("ip")!, db = categoryByKey("databases")!, srv = categoryByKey("servers")!;
    expect(share(total, { count: 526 }, 526)).toBeNull();
    expect(share(ip, { count: 14, assets: 14 }, 526)).toBeCloseTo(2.66, 2);
    // More addresses than assets holding them: the share follows the assets.
    expect(share(ip, { count: 20, assets: 14 }, 526)).toBeCloseTo(2.66, 2);
    expect(share(ip, { count: 14, assets: null }, 526)).toBeNull();
    expect(share(db, { count: 1, assets: 1 }, 526)).toBeCloseTo(0.19, 2);
    expect(share(db, { count: null }, 526)).toBeNull();
    expect(share(db, { count: 1, assets: 1 }, null)).toBeNull();
    expect(share(db, { count: 0, assets: 0 }, 0)).toBeNull();
    expect(share(srv, { count: null }, 526)).toBeNull();
    expect([fmtShare(null), fmtShare(0), fmtShare(100), fmtShare(0.19), fmtShare(2.66), fmtShare(97.34)]).toEqual(["—", "0%", "100%", "0.2%", "2.7%", "97%"]);
  });

  it("splits the inventory exactly by current address, so segments sum to the total and nothing counts twice", () => {
    const assets = [asset("a", { address: "10.0.0.1" }), asset("b", { address: "10.0.0.2" }), asset("c"), asset("d"), asset("e")];
    const segs = distribution(assets);
    expect(segs).toEqual([
      { key: "addressed", label: "With a current IP address", color: categoryByKey("ip")!.color, value: 2 },
      { key: "unaddressed", label: "No current IP address", color: "#64748B", value: 3 },
    ]);
    expect(segs.reduce((n, s) => n + s.value, 0)).toBe(assets.length);
    // A zero segment is left out; an unread inventory draws nothing.
    expect(distribution([asset("c")]).map((s) => s.key)).toEqual(["unaddressed"]);
    expect(distribution([])).toEqual([]);
    expect(distribution(undefined)).toEqual([]);
  });

  it("gives every non-zero segment a visible arc, taking the difference from the largest", () => {
    const circ = 2 * Math.PI * 74;
    const segs = [{ key: "addressed", label: "", color: "", value: 14 }, { key: "unaddressed", label: "", color: "", value: 512 }];
    const a = arcs(segs, circ);
    expect(a.map((x) => x.key)).toEqual(["addressed", "unaddressed"]);
    expect(a[0].len).toBeCloseTo((14 / 526) * circ - 2, 5);
    expect(a[1].start).toBeCloseTo((14 / 526) * circ, 5);
    // A tiny share still gets the minimum arc.
    const tiny = arcs([{ ...segs[0], value: 1 }, { ...segs[1], value: 100000 }], circ);
    expect(tiny[0].len).toBeCloseTo(6 - 2, 5);
    expect(tiny[0].len + 2 + tiny[1].len + 2).toBeCloseTo(circ, 5);
    // One segment is the whole ring, with no gap.
    expect(arcs([segs[1]], circ)[0].len).toBeCloseTo(circ, 5);
    expect(arcs([], circ)).toEqual([]);
    expect(arcs([{ ...segs[0], value: 0 }], circ)).toEqual([]);
  });

  it("types an asset from its stored device type, else as a database host, else Unknown — never from an address", () => {
    expect(assetKind(asset("a", { device_type: "server" }))).toMatchObject({ label: "Server", icon: "server", known: true });
    expect(assetKind(asset("a", { device_type: "Edge Router" }))).toMatchObject({ label: "Network Device", icon: "router" });
    expect(assetKind(asset("a", { device_type: "laptop" }))).toMatchObject({ label: "Laptop", icon: "laptop" });
    expect(assetKind(asset("a"), [{ asset_id: "a", service: "mysql" }])).toMatchObject({ label: "Database", icon: "database", color: "#F43F5E", known: true });
    expect(assetKind(asset("a"), [{ asset_id: "a", service: "ssh" }])).toMatchObject({ label: "Unknown", icon: "help", known: false });
    expect(assetKind(asset("a", { address: "10.0.0.9" }))).toMatchObject({ label: "Unknown", known: false });
    expect(assetKind(asset("a", { device_type: "toaster" }))).toMatchObject({ label: "Unknown", known: false });
    // The stored device type wins over the open-port evidence.
    expect(assetKind(asset("a", { device_type: "server" }), [{ asset_id: "a", service: "mysql" }]).label).toBe("Server");
    // Card and row use the same icon and colour for a category.
    const db = categoryByKey("databases")!;
    expect(assetKind(asset("a"), [{ asset_id: "a", service: "postgresql" }])).toMatchObject({ icon: db.icon, color: db.color, dark: db.dark });
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
