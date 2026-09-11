import { describe, expect, it } from "vitest";
import { applyTriageFilter, attention, confidenceBand, kevInversion, score, tally, worstFirst } from "./console";
import type { FindingSummary, KnowledgeFeed, ScanPoint } from "./api";

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
