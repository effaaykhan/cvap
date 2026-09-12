import { describe, expect, it } from "vitest";
import { advisory, ageRatio, applyTriageFilter, attention, confidenceBand, kevInversion, scanReadiness, score, sparkPath, stackSegments, tally, trendGeometry, worstFirst, yTicks, exactRead, provenanceAge } from "./console";
import type { FindingSummary, Health, KnowledgeFeed, ScanPoint } from "./api";

const f = (over: Partial<FindingSummary>): FindingSummary => ({
  id: "f", asset_id: "a", category: "vulnerability", confidence: 0.9, exposure_zones: 1,
  first_seen: "2026-09-01T00:00:00Z", last_seen: "2026-09-01T00:00:00Z", kev: false,
  priority_basis: "CVSS 7.5", rule: "CVE-0000-0001", severity: "high", status: "open", ...over,
});

describe("tally", () => {
  it("is exact only when the page was complete", () => {
    const rows = [f({ kev: true }), f({ kev: false })];
    expect(tally(rows, true, (x) => x.kev)).toEqual({ value: 1, exact: true, sample: 2 });
    expect(tally(rows, false, (x) => x.kev).exact).toBe(false);
  });
});

describe("applyTriageFilter", () => {
  const rows = [f({ id: "1", kev: true, severity: "high", asset_hostname: "db-01" }),
    f({ id: "2", kev: false, severity: "critical", rule: "CVE-2007-2447" }),
    f({ id: "3", kev: false, severity: "medium" })];
  it("keeps the priority rank when narrowing", () => {
    const out = applyTriageFilter(rows, { kevOnly: false, band: "critical+high", q: "" });
    expect(out.map((x) => x.rank)).toEqual([1, 2]);
  });
  it("kev only and search narrow without re-ranking", () => {
    expect(applyTriageFilter(rows, { kevOnly: true, band: "", q: "" }).map((x) => x.id)).toEqual(["1"]);
    const hit = applyTriageFilter(rows, { kevOnly: false, band: "", q: "2007-2447" });
    expect(hit.map((x) => x.rank)).toEqual([2]);
  });
});

describe("score and confidence", () => {
  it("renders unscored as a dash, never 0", () => {
    expect(score(null, 5)).toBe("—");
    expect(score(undefined, 1)).toBe("—");
    expect(score(0.99998, 5)).toBe("0.99998");
  });
  it("bands confidence at the shipped thresholds", () => {
    expect(confidenceBand(0.9)).toBe("high");
    expect(confidenceBand(0.6)).toBe("medium");
    expect(confidenceBand(0.59)).toBe("low");
    expect(confidenceBand(undefined)).toBe("low");
  });
});

const sp = (health: string, hostname: string): ScanPoint => ({
  id: hostname, hostname, health, status: "online", zone_id: "z", agent_version: "0", protocol_version: "v1",
  capabilities: [], leases_held: 0,
});

describe("worstFirst and attention", () => {
  it("orders offline before degraded before healthy", () => {
    const out = worstFirst([sp("healthy", "c"), sp("degraded", "b"), sp("offline", "a")]);
    expect(out.map((p) => p.health)).toEqual(["offline", "degraded", "healthy"]);
  });
  it("lists only server-stated problems, never inferred ones", () => {
    const feeds: KnowledgeFeed[] = [
      { feed: "usn", state: "current", advisory_count: 1, source_url: "", staleness_threshold_seconds: 86400 },
      { feed: "epss", state: "stale", advisory_count: 1, source_url: "", staleness_threshold_seconds: 172800, last_fetched_at: "2026-09-01T00:00:00Z" },
    ];
    const out = attention([sp("offline", "sp-dmz-1"), sp("healthy", "sp-core-1")], feeds, []);
    expect(out.map((a) => a.text)).toEqual(["scan point sp-dmz-1 offline", "epss feed stale"]);
    expect(out[0].level).toBe("danger");
  });
});

describe("kevInversion", () => {
  it("is true only when a KEV finding sits above a higher-CVSS non-KEV one", () => {
    const kev = f({ kev: true, cvss: 7.5 });
    const samba = f({ kev: false, cvss: 10 });
    expect(kevInversion([kev, samba])).toBe(true);
    expect(kevInversion([samba, kev])).toBe(false);
    expect(kevInversion([kev, f({ kev: false, cvss: null })])).toBe(false);
  });
});

describe("attention with the health read", () => {
  it("names a pressed kill switch and a blocked scan ahead of feeds", () => {
    const health: Health = {
      blocked_scans: [{ id: "9c2d41aa-1", scan_type: "discovery", status: "running", policy_id: "p", engine: "discovery", reason: "no online scan point with the discovery engine enabled in a zone this policy allows" }],
      ingest_backlog: 0, unresolved_observations: 0, kill_switch_state: "active",
      active_kills: [{ id: "k", scope: "tenant", issued_at: "2026-09-11T00:00:00Z", reason: "runaway", unacknowledged: 2 }],
      credential_grants_unconfirmed: 0, scope_enforcement_sites: 2, computed_at: "2026-09-11T00:00:00Z",
    };
    const out = attention([], [], [], health);
    expect(out.map((a) => a.text)).toEqual(["kill switch active (tenant)", "scan 9c2d41aa blocked"]);
    expect(out[0].level).toBe("danger");
  });
});

describe("trendGeometry", () => {
  it("uses one scale for both series and closes the area on the baseline", () => {
    const g = trendGeometry([{ day: "d1", open: 10, kev: 1 }, { day: "d2", open: 20, kev: 2 }], 100, 50, 0);
    expect(g.max).toBe(20);
    expect(g.open).toBe("M0.0,25.0 L100.0,0.0");
    expect(g.kev).toBe("M0.0,47.5 L100.0,45.0");
    expect(g.area.endsWith("L100.0,50.0 L0.0,50.0 Z")).toBe(true);
  });
  it("never divides by zero on an empty or flat series", () => {
    expect(trendGeometry([], 100, 50).open).toBe("");
    expect(trendGeometry([{ day: "d", open: 0, kev: 0 }], 100, 50).max).toBe(1);
  });
});

describe("chart geometry", () => {
  it("stacks segments to at most 100 percent and drops zeros", () => {
    const { total, segments } = stackSegments([["critical", 4], ["high", 21], ["info", 0]]);
    expect(total).toBe(25);
    expect(segments.map((s) => s.key)).toEqual(["critical", "high"]);
    expect(segments.reduce((n, s) => n + s.pct, 0)).toBeCloseTo(100);
    expect(stackSegments([["a", 0]]).segments).toEqual([]);
  });
  it("draws a sparkline that ends at the last value and closes on the baseline", () => {
    const s = sparkPath([1, 2, 4], 40, 10);
    expect(s.line).toBe("M0.0,7.5 L20.0,5.0 L40.0,0.0");
    expect(s.last).toEqual({ x: 40, y: 0 });
    expect(s.area.endsWith("L40.0,10 L0.0,10 Z")).toBe(true);
    expect(sparkPath([], 40, 10).last).toBeNull();
  });
  it("labels the top gridline with a round number the data reaches", () => {
    expect(yTicks(147)).toEqual([0, 100, 200]);
    expect(yTicks(20)).toEqual([0, 10, 20]);
    expect(yTicks(0)).toEqual([0]);
  });
  it("measures feed age against the feed's own threshold", () => {
    const now = Date.parse("2026-09-11T12:00:00Z");
    expect(ageRatio("2026-09-11T00:00:00Z", 86400, now)).toBeCloseTo(0.5);
    expect(ageRatio(null, 86400, now)).toBeNull();
  });
});

describe("advisory and scan readiness", () => {
  it("never explains cannot-know as clean", () => {
    expect(advisory("cannot_know").tone).not.toBe("ok");
    expect(advisory("clean").tone).toBe("ok");
    expect(advisory(undefined).label).toBe("unknown");
  });
  it("names why a scan cannot run", () => {
    const off = [sp("offline", "sp-1")];
    off[0].capabilities = ["discovery"];
    const r = scanReadiness(off, "discovery", [{ id: "r", effect: "allow", match_type: "cidr", match_value: "10.0.0.0/8", precedence: 0 }]);
    expect(r.ok).toBe(false);
    expect(r.reasons[0]).toContain("none healthy");
    const on = [sp("healthy", "sp-1")];
    on[0].capabilities = ["discovery"];
    expect(scanReadiness(on, "discovery", []).reasons[0]).toContain("no allow rule");
    expect(scanReadiness(on, "host", []).reasons[0]).toContain("no enrolled scan point has the host engine");
  });
});

describe("exactRead (ADR-095)", () => {
  it("recognises the object shape and ignores the vote array", () => {
    expect(exactRead([{ service: "ssh", port: 22, family: "ubuntu", role: "contributed" }])).toBeNull();
    expect(exactRead(null)).toBeNull();
    expect(exactRead({ source: "band_vote" })).toBeNull();
    expect(exactRead({ source: "package_manager", release: "jammy", read_at: "2026-09-11T16:11:43Z" }))
      .toEqual({ source: "package_manager", readAt: "2026-09-11T16:11:43Z" });
    expect(exactRead({ source: "os-release", family: "ubuntu" })).toEqual({ source: "os-release", readAt: undefined });
  });
});

describe("provenanceAge", () => {
  const now = Date.parse("2026-09-12T12:00:00Z");
  it("reports days, then hours, then less than an hour", () => {
    expect(provenanceAge("2026-09-09T12:00:00Z", now)).toBe("3 days ago");
    expect(provenanceAge("2026-09-11T12:00:00Z", now)).toBe("1 day ago");
    expect(provenanceAge("2026-09-12T09:30:00Z", now)).toBe("2 hours ago");
    expect(provenanceAge("2026-09-12T11:50:00Z", now)).toBe("less than an hour ago");
    expect(provenanceAge("2026-09-13T00:00:00Z", now)).toBe("just now");
    expect(provenanceAge("not a date", now)).toBe("");
  });
});
