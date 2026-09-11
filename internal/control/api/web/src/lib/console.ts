// Pure helpers behind the console surfaces (Overview, Triage, Health). No I/O,
// so each rule about what a number MEANS can be tested on its own: rung 1 of the
// console design is "accurate first — nothing overstates weak data", and these
// are where that is decided rather than in JSX.
import type { FindingSummary, Health, KnowledgeFeed, ScanPoint, Scan, TrendPoint } from "./api";

// A page of findings is complete when the server handed back no cursor. Counts
// over a complete page are exact; counts over a truncated one are "of the first
// N", and the caller must say which — a count that quietly stops at the page
// size is the silent-success class the design was written against.
export type Tally = { value: number; exact: boolean; sample: number };

export function tally(findings: FindingSummary[], complete: boolean, pred: (f: FindingSummary) => boolean): Tally {
  return { value: findings.filter(pred).length, exact: complete, sample: findings.length };
}

export const isKEV = (f: FindingSummary) => f.kev === true;
export const isOpenish = (f: FindingSummary) => f.status === "open" || f.status === "confirmed";

// Triage filters applied WITHIN a page. The server orders and pages by
// priority; these narrow what is shown without re-ordering, so rank numbers
// keep meaning "position in the priority order", not "position after filtering".
export type TriageFilter = { kevOnly: boolean; band: "" | "critical+high"; q: string };

export function applyTriageFilter(findings: FindingSummary[], f: TriageFilter): (FindingSummary & { rank: number })[] {
  const q = f.q.trim().toLowerCase();
  return findings
    .map((x, i) => ({ ...x, rank: i + 1 }))
    .filter((x) => !f.kevOnly || x.kev)
    .filter((x) => f.band !== "critical+high" || x.severity === "critical" || x.severity === "high")
    .filter(
      (x) =>
        !q ||
        x.rule.toLowerCase().includes(q) ||
        (x.asset_hostname ?? "").toLowerCase().includes(q) ||
        x.asset_id.toLowerCase().includes(q) ||
        (x.instance_locator ?? "").toLowerCase().includes(q),
    );
}

// EPSS/CVSS: null is UNSCORED — a dash, never 0 (ADR-069).
export function score(v: number | null | undefined, digits: number): string {
  return v == null ? "—" : v.toFixed(digits);
}

// Confidence is shown as its value and a band. The band drives the lane dot;
// the label never claims a SOURCE the summary does not carry (advisory-matched
// versus banner-inferred lives on the detail, where has_vuln_def says which).
export type ConfidenceBand = "high" | "medium" | "low";
export function confidenceBand(v: number | null | undefined): ConfidenceBand {
  const c = v ?? 0;
  return c >= 0.85 ? "high" : c >= 0.6 ? "medium" : "low";
}

// Scan points, worst first: the states the server synthesises (handlers_ops.go)
// in the order an operator needs to see them.
const SP_ORDER: Record<string, number> = { offline: 0, degraded: 1, pending: 2, revoked: 3, disabled: 4, healthy: 5 };
export function worstFirst(points: ScanPoint[]): ScanPoint[] {
  return [...points].sort((a, b) => (SP_ORDER[a.health] ?? 9) - (SP_ORDER[b.health] ?? 9) || a.hostname.localeCompare(b.hostname));
}

// What is "not working" from the reads that exist today. Each entry names its
// source so nothing here is inferred client-side beyond the server's own state
// words. Blocked-for-capacity, ingest backlog and kill-switch state have no read
// yet (console spec, backend table) and are NOT synthesised from anything else.
export type Attention = { level: "danger" | "warn"; text: string; detail: string; to: string };

export function attention(points: ScanPoint[], feeds: KnowledgeFeed[], scans: Scan[], health?: Health): Attention[] {
  const out: Attention[] = [];
  // Server-owned pipeline state first: a pressed kill switch and a scan that
  // cannot run outrank a stale feed.
  if (health) {
    for (const k of health.active_kills)
      out.push({ level: "danger", text: `kill switch active (${k.scope})`, detail: `${k.reason} · ${k.unacknowledged} scan point${k.unacknowledged === 1 ? "" : "s"} not yet acknowledged`, to: "/health" });
    for (const b of health.blocked_scans)
      out.push({ level: "warn", text: `scan ${b.id.slice(0, 8)} blocked`, detail: b.reason, to: `/scans/${b.id}` });
    if (health.ingest_backlog > 0)
      out.push({ level: "warn", text: `ingest backlog ${health.ingest_backlog}`, detail: "observations pending over an hour; results never attested complete", to: "/health" });
    if (health.credential_grants_unconfirmed > 0)
      out.push({ level: "warn", text: `${health.credential_grants_unconfirmed} credential grant${health.credential_grants_unconfirmed === 1 ? "" : "s"} unconfirmed`, detail: "past expiry with no zeroisation attestation", to: "/health" });
  }
  for (const p of worstFirst(points)) {
    if (p.health === "offline")
      out.push({ level: "danger", text: `scan point ${p.hostname} offline`, detail: p.health_reason ?? "", to: "/health" });
    else if (p.health === "degraded")
      out.push({ level: "warn", text: `scan point ${p.hostname} degraded`, detail: p.health_reason ?? "", to: "/health" });
  }
  for (const f of feeds) {
    if (f.state === "stale")
      out.push({ level: "warn", text: `${f.feed} feed stale`, detail: `fetched ${ago(f.last_fetched_at)}; threshold ${threshold(f.staleness_threshold_seconds)}`, to: "/knowledge" });
    else if (f.state === "never")
      out.push({ level: "warn", text: `${f.feed} feed never fetched`, detail: "advisory matching against it finds nothing", to: "/knowledge" });
  }
  for (const s of scans) {
    if (s.status === "failed")
      out.push({ level: "warn", text: `scan ${s.id.slice(0, 8)} failed`, detail: `${s.scan_type} · created ${ago(s.created_at)}`, to: `/scans/${s.id}` });
  }
  return out;
}

export function ago(iso: string | null | undefined): string {
  if (!iso) return "never";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "unknown";
  const secs = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (secs < 90) return `${secs}s ago`;
  const mins = Math.round(secs / 60);
  if (mins < 90) return `${mins}m ago`;
  const hours = Math.round(mins / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

export function threshold(seconds: number): string {
  const days = Math.round(seconds / 86400);
  return days >= 1 ? `${days}d` : `${Math.round(seconds / 3600)}h`;
}

export function fmtTime(t?: string | null): string {
  return t ? new Date(t).toLocaleString() : "—";
}

// The worked example from the console spec: a KEV-listed finding outranks a
// non-KEV one with a higher CVSS. True when the visible order shows it, so the
// caption explaining priority-not-severity appears only when there is
// something to explain.
export function kevInversion(rows: FindingSummary[]): boolean {
  return rows.some((f, i) => f.kev && rows.slice(i + 1).some((g) => !g.kev && (g.cvss ?? -1) > (f.cvss ?? -1)));
}

// Trend geometry, pure so the chart's scale is testable: one y scale for both
// series (open and its KEV subset share a unit), x spread evenly over the days,
// the path closed under the open line for the area fill. Never a dual axis.
export type TrendGeometry = { open: string; kev: string; area: string; max: number; xs: number[]; ys: number[] };

export function trendGeometry(points: TrendPoint[], width: number, height: number, pad = 4): TrendGeometry {
  const n = points.length;
  const max = Math.max(1, ...points.map((p) => p.open));
  const x = (i: number) => (n <= 1 ? width / 2 : pad + (i * (width - 2 * pad)) / (n - 1));
  const y = (v: number) => height - pad - ((height - 2 * pad) * v) / max;
  const line = (pick: (p: TrendPoint) => number) => points.map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(pick(p)).toFixed(1)}`).join(" ");
  const open = line((p) => p.open);
  const area = n ? `${open} L${x(n - 1).toFixed(1)},${(height - pad).toFixed(1)} L${x(0).toFixed(1)},${(height - pad).toFixed(1)} Z` : "";
  return { open, kev: line((p) => p.kev), area, max, xs: points.map((_, i) => x(i)), ys: points.map((p) => y(p.open)) };
}
