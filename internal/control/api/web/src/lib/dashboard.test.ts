import { describe, expect, it, vi } from "vitest";
import {
  allAssets, allFindings, arcs, assetKind, CATEGORIES, categoryByKey, distribution, fmtShare, inRange, KIND_KEYS, kindKey,
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
  const typed = (id: string, device_type: string, extra = {}) => asset(id, { device_type, ...extra });

  it("holds the eleven categories in the required order, Other Assets removed, each with its own colour and icon", () => {
    expect(CATEGORIES.map((c) => c.label)).toEqual([
      "Total Assets", "IP Addresses", "Servers", "Laptops", "APIs", "Web Applications",
      "Docker Containers", "Kubernetes Clusters", "Databases", "Cloud Assets", "Network Devices",
    ]);
    expect(categoryByKey("other")).toBeUndefined();
    expect(new Set(CATEGORIES.map((c) => c.color)).size).toBe(11);
    expect(new Set(CATEGORIES.map((c) => c.icon)).size).toBe(11);
    expect(CATEGORIES.every((c) => /^#[0-9A-F]{6}$/.test(c.color) && /^#[0-9A-F]{6}$/.test(c.deep) && c.deep !== c.color)).toBe(true);
    // Only what Core measures leads somewhere real; everything else explains its gap.
    expect(CATEGORIES.filter((c) => c.to).map((c) => c.key)).toEqual(["total", "ip", "databases"]);
    expect(CATEGORIES.filter((c) => !c.to).every((c) => !!c.gap)).toBe(true);
    // Total and IP Addresses are not kinds of asset.
    expect(KIND_KEYS).toEqual(["servers", "laptops", "apis", "webapps", "docker", "k8s", "databases", "cloud", "network"]);
  });

  it("keeps each bold glyph at 3:1 or better against its tinted tile, in both themes", () => {
    const rgb = (hex: string) => [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16));
    const lum = ([r, g, b]: number[]) => {
      const [R, G, B] = [r, g, b].map((v) => v / 255).map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
      return 0.2126 * R + 0.7152 * G + 0.0722 * B;
    };
    const mix = (a: number[], b: number[], t: number) => a.map((v, i) => v * t + b[i] * (1 - t));
    const ratio = (x: number[], y: number[]) => { const [l1, l2] = [lum(x), lum(y)].sort((p, q) => q - p); return (l1 + 0.05) / (l2 + 0.05); };
    for (const c of CATEGORIES) {
      // Dark theme: 17% of the colour over the dark surface, glyph in the colour.
      expect(ratio(rgb(c.color), mix(rgb(c.color), rgb("#161B22"), 0.17))).toBeGreaterThanOrEqual(3);
      // Light theme: 13% of the colour over white, glyph in the deeper shade.
      expect(ratio(rgb(c.deep), mix(rgb(c.color), rgb("#FFFFFF"), 0.13))).toBeGreaterThanOrEqual(3);
    }
  });

  it("gives each asset at most one kind: stored device type first, then a database service, else none", () => {
    expect(kindKey(typed("a", "server"))).toBe("servers");
    expect(kindKey(typed("a", "Edge Router"))).toBe("network");
    expect(kindKey(typed("a", "docker container"))).toBe("docker");
    expect(kindKey(asset("a"), [{ asset_id: "a", service: "mysql" }])).toBe("databases");
    // The stored type wins, so a server running MySQL is one server, not also a database.
    expect(kindKey(typed("a", "server"), [{ asset_id: "a", service: "mysql" }])).toBe("servers");
    expect(kindKey(asset("a"), [{ asset_id: "a", service: "ssh" }])).toBeNull();
    expect(kindKey(asset("a", { address: "10.0.0.9" }))).toBeNull();
    expect(kindKey(typed("a", "toaster"))).toBeNull();
    expect(assetKind(asset("a"))).toMatchObject({ label: "Unknown", icon: "help", known: false });
    const db = categoryByKey("databases")!;
    expect(assetKind(asset("a"), [{ asset_id: "a", service: "postgresql" }])).toMatchObject({ label: "Database", icon: db.icon, color: db.color, deep: db.deep, known: true });
  });

  it("measures what Core holds today: total, addresses, database hosts and the remainder; device kinds read —", () => {
    const ms = measure({ assets: [asset("a", { address: "10.0.0.1" }), asset("b"), asset("c")], addresses: 5, openPorts: ports([["a", "mysql"], ["a", "postgresql"], ["b", "ssh"]]) });
    expect(ms.total).toMatchObject({ count: 3, assets: 3 });
    // IP Addresses counts addresses; the assets holding one are what its share is taken from.
    expect(ms.ip).toMatchObject({ count: 5, assets: 1 });
    expect(ms.ip.note).toContain("held by 1 of the 3 assets");
    // One host with two engines is one database host.
    expect(ms.databases).toMatchObject({ count: 1, assets: 1 });
    expect(ms.unclassified).toMatchObject({ count: 2 });
    // No asset carries a device type, so a 0 there would claim a classification never made.
    for (const k of ["servers", "laptops", "apis", "webapps", "docker", "k8s", "cloud", "network"] as const) expect(ms[k].count).toBeNull();
  });

  it("starts counting device kinds — zeros included — as soon as Core stores a device type", () => {
    const ms = measure({ assets: [typed("a", "server"), typed("b", "server"), typed("c", "laptop"), asset("d"), asset("e")], addresses: 0, openPorts: ports([["d", "mysql"]]) });
    expect([ms.servers.count, ms.laptops.count, ms.network.count, ms.cloud.count, ms.databases.count, ms.unclassified.count]).toEqual([2, 1, 0, 0, 1, 1]);
    // The kinds and the remainder partition the inventory exactly.
    const sum = KIND_KEYS.reduce((n, k) => n + (ms[k].count ?? 0), 0) + ms.unclassified.count!;
    expect(sum).toBe(5);
  });

  it("reads Databases and the remainder as — past the open-port cap, keeping a lower bound", () => {
    const ms = measure({ assets: [asset("a"), asset("b")], addresses: 0, openPorts: ports([["a", "mysql"]], true) });
    expect(ms.databases.count).toBeNull();
    expect(ms.databases.atLeast).toBe(1);
    expect(ms.databases.note).toContain("500");
    expect(ms.unclassified.count).toBeNull();
    // A device-typed kind stays exact: it never depends on the port read.
    const typedMs = measure({ assets: [typed("a", "server"), asset("b")], addresses: 0, openPorts: ports([], true) });
    expect(typedMs.servers.count).toBe(1);
  });

  it("counts nothing that has not loaded, never zero", () => {
    const ms = measure({});
    expect([ms.total.count, ms.ip.count, ms.databases.count, ms.unclassified.count]).toEqual([null, null, null, null]);
    const noPorts = measure({ assets: [asset("a")], addresses: 0 });
    expect([noPorts.total.count, noPorts.databases.count, noPorts.unclassified.count]).toEqual([1, null, null]);
  });

  it("takes every share over the inventory: Total is the classified share, IP the addressed assets, never 526 + 14", () => {
    const assets = [...Array.from({ length: 14 }, (_, i) => asset(`ip${i}`, { address: `10.0.0.${i}` })), ...Array.from({ length: 512 }, (_, i) => asset(`n${i}`))];
    const ms = measure({ assets, addresses: 14, openPorts: ports([["n0", "mysql"]]) });
    expect(share("ip", ms)).toBeCloseTo((100 * 14) / 526, 6);
    expect(share("databases", ms)).toBeCloseTo((100 * 1) / 526, 6);
    expect(share("unclassified", ms)).toBeCloseTo((100 * 525) / 526, 6);
    // Total Assets: the classified share (1 database host of 526), never a 100% of itself.
    expect(share("total", ms)).toBeCloseTo((100 * 1) / 526, 6);
    // Unmeasured kinds and an unmeasured remainder have no share.
    expect(share("servers", ms)).toBeNull();
    const capped = measure({ assets, addresses: 14, openPorts: ports([["n0", "mysql"]], true) });
    expect([share("total", capped), share("databases", capped), share("unclassified", capped)]).toEqual([null, null, null]);
    expect(share("ip", capped)).toBeCloseTo((100 * 14) / 526, 6);
    // A zero denominator is —.
    expect(share("ip", measure({ assets: [], addresses: 0, openPorts: ports([]) }))).toBeNull();
    expect([fmtShare(null), fmtShare(0), fmtShare(100), fmtShare(0.19), fmtShare(2.66), fmtShare(97.34)]).toEqual(["—", "0%", "100%", "0.2%", "2.7%", "97%"]);
    // Never all or none when it is neither: 428 of 430, 1 of 2,000, 1,999 of 2,000.
    expect([fmtShare((100 * 428) / 430), fmtShare(0.05), fmtShare(99.95), fmtShare(99.4)]).toEqual(["99.5%", "<0.1%", ">99.9%", "99%"]);
  });

  it("draws one segment per measured kind with assets, then the remainder, summing to the total", () => {
    const ms = measure({ assets: [typed("a", "server"), typed("b", "server"), typed("c", "router"), asset("d"), asset("e"), asset("f")], addresses: 2, openPorts: ports([["d", "mysql"]]) });
    const segs = distribution(ms);
    expect(segs.map((s) => [s.key, s.value, s.color])).toEqual([
      ["servers", 2, categoryByKey("servers")!.color], ["databases", 1, categoryByKey("databases")!.color],
      ["network", 1, categoryByKey("network")!.color], ["unclassified", 2, "#64748B"],
    ]);
    expect(segs.reduce((n, s) => n + s.value, 0)).toBe(ms.total.count);
    // IP Addresses and Total are never segments; zero kinds are left out.
    expect(segs.some((s) => s.key === "ip" || s.key === "total" || s.key === "laptops")).toBe(false);
    // Today's shape: one database host, the rest unclassified.
    expect(distribution(measure({ assets: [asset("a"), asset("b")], addresses: 0, openPorts: ports([["a", "mysql"]]) })).map((s) => s.key)).toEqual(["databases", "unclassified"]);
    // Capped and untyped: nothing exact to draw.
    expect(distribution(measure({ assets: [asset("a")], addresses: 0, openPorts: ports([["a", "mysql"]], true) }))).toEqual([]);
    expect(distribution(measure({}))).toEqual([]);
  });

  it("sizes each arc against the whole inventory, keeps a small one visible, and leaves unmeasured parts empty", () => {
    const circ = 2 * Math.PI * 74;
    const seg = (key: string, value: number) => ({ key, label: key, color: "", value });
    const a = arcs([seg("databases", 1), seg("unclassified", 525)], 526, circ);
    // The 0.19% segment gets the minimum, taken from the largest; together they fill the ring.
    expect(a[0].len).toBeCloseTo(4, 5);
    expect(a[0].len + 2 + a[1].len + 2).toBeCloseTo(circ, 5);
    // Proportional when large enough.
    const b = arcs([seg("servers", 100), seg("unclassified", 100)], 200, circ);
    expect(b[0].len).toBeCloseTo(circ / 2 - 2, 5);
    // Only part of the inventory measured: the arcs cover only that part.
    const c = arcs([seg("servers", 50)], 200, circ);
    expect(c[0].len).toBeCloseTo(circ / 4, 5);
    expect(arcs([], 10, circ)).toEqual([]);
    expect(arcs([seg("x", 0)], 10, circ)).toEqual([]);
    expect(arcs([seg("x", 3)], 0, circ)).toEqual([]);
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
