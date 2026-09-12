// Pure helpers behind the console surfaces (Overview, Triage, Health). No I/O,
// so each rule about what a number MEANS can be tested on its own: rung 1 of the
// console design is "accurate first — nothing overstates weak data", and these
// are where that is decided rather than in JSX.
import type { FindingSummary, Health, KnowledgeFeed, ScanPoint, Scan, ScopeRule, TrendPoint } from "./api";

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

// ---- chart geometry, pure ---------------------------------------------------

// A stacked horizontal bar: each segment's width as a percentage of the total,
// never summing past 100, with a zero total drawing nothing rather than NaN.
export type Segment = { key: string; value: number; pct: number };
export function stackSegments(entries: Array<[string, number]>): { total: number; segments: Segment[] } {
  const total = entries.reduce((n, [, v]) => n + Math.max(0, v), 0);
  const segments = entries
    .filter(([, v]) => v > 0)
    .map(([key, value]) => ({ key, value, pct: total ? (100 * value) / total : 0 }));
  return { total, segments };
}

// A sparkline path over a value series in a box, baseline at the bottom.
export function sparkPath(values: number[], width: number, height: number): { line: string; area: string; last: { x: number; y: number } | null } {
  const n = values.length;
  if (n === 0) return { line: "", area: "", last: null };
  const max = Math.max(1, ...values);
  const x = (i: number) => (n === 1 ? width / 2 : (i * width) / (n - 1));
  const y = (v: number) => height - (height * v) / max;
  const line = values.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
  const area = `${line} L${x(n - 1).toFixed(1)},${height} L${x(0).toFixed(1)},${height} Z`;
  return { line, area, last: { x: x(n - 1), y: y(values[n - 1]) } };
}

// Nice y-axis ticks for a max value: 0, mid, top, where top is the smallest
// round number at or above the data max so the top gridline is labelled with
// a value the chart reaches or nearly reaches.
export function yTicks(max: number): number[] {
  if (max <= 0) return [0];
  const mag = Math.pow(10, Math.floor(Math.log10(max)));
  const steps = [1, 2, 2.5, 5, 10];
  const top = steps.map((s) => s * mag).find((v) => v >= max) ?? max;
  return [0, top / 2, top];
}

// Feed age as a fraction of its own staleness threshold: 1.0 is the line the
// server calls stale. Capped at 2 for drawing; the number itself is shown raw.
export function ageRatio(lastFetched: string | null | undefined, thresholdSeconds: number, now = Date.now()): number | null {
  if (!lastFetched || thresholdSeconds <= 0) return null;
  const age = (now - new Date(lastFetched).getTime()) / 1000;
  if (!Number.isFinite(age)) return null;
  return Math.max(0, age / thresholdSeconds);
}

// The advisory posture words (ADR-068), explained from the operator's side of
// the screen. "clean" is a real verdict; "cannot_know" and "no_release" are
// honest gaps, never silence dressed as safety.
export const ADVISORY: Record<string, { label: string; tone: string; why: string }> = {
  vulnerable: { label: "vulnerable", tone: "critical", why: "at least one installed package matches a vendor advisory that fixes a known CVE" },
  clean: { label: "clean", tone: "ok", why: "its release is resolved and inside advisory coverage, and no installed package matches an advisory" },
  cannot_know: { label: "cannot know", tone: "warn", why: "its release is past its vendor's advisory window, so a missing match proves nothing" },
  no_release: { label: "no release", tone: "muted", why: "no release could be attributed, so advisory matching has nothing to key on; a credentialed read or a fingerprint scan resolves it" },
};

export function advisory(status: string | undefined): { label: string; tone: string; why: string } {
  return ADVISORY[status ?? ""] ?? { label: status || "unknown", tone: "muted", why: "no advisory posture is recorded for this system" };
}

// One line that says whether a scan can run right now, from the reads that
// decide it: online capable scan points, a policy with an allow rule.
export function scanReadiness(points: ScanPoint[], engine: string, rules: ScopeRule[] | undefined): { ok: boolean; reasons: string[] } {
  const reasons: string[] = [];
  const capable = points.filter((p) => p.health === "healthy" && p.capabilities.includes(engine));
  if (capable.length === 0) {
    const anyEngine = points.some((p) => p.capabilities.includes(engine));
    reasons.push(anyEngine
      ? `no scan point with the ${engine} engine is online (${points.length} enrolled, none healthy)`
      : `no enrolled scan point has the ${engine} engine`);
  }
  if (rules && !rules.some((r) => r.effect === "allow")) {
    reasons.push("the policy has no allow rule, so every target would be refused as out of scope");
  }
  return { ok: reasons.length === 0, reasons };
}

// exactRead recognises the object-shaped provenance an exact host read writes
// (ADR-090/095): {source: "os-release" | "package_manager", read_at?: RFC3339}.
// Inferred attribution is an ARRAY of votes; the two shapes must never be
// confused, because an exact read outranks any later inference and a page that
// assumed an array threw on the object.
export function exactRead(p: unknown): { source: string; readAt?: string } | null {
  if (!p || Array.isArray(p) || typeof p !== "object") return null;
  const o = p as { source?: unknown; read_at?: unknown };
  if (o.source !== "os-release" && o.source !== "package_manager") return null;
  return { source: o.source, readAt: typeof o.read_at === "string" ? o.read_at : undefined };
}

// provenanceAge says how old an exact read is, in the coarsest unit that is
// still honest: a host that stops answering credentialed keeps its last exact
// value, and the operator must see the age grow rather than the value revert.
export function provenanceAge(iso: string, now: number = Date.now()): string {
  const ms = now - new Date(iso).getTime();
  if (!Number.isFinite(ms)) return ""; // unreadable: say nothing rather than claim freshness
  if (ms < 0) return "just now";
  const d = Math.floor(ms / 86_400_000);
  if (d >= 1) return `${d} day${d === 1 ? "" : "s"} ago`;
  const h = Math.floor(ms / 3_600_000);
  return h >= 1 ? `${h} hour${h === 1 ? "" : "s"} ago` : "less than an hour ago";
}
