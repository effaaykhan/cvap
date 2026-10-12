// Pure helpers behind the Running Scans page. No I/O. Every value here comes
// from a field /v1/scans serves (ScanResponse); nothing estimates progress,
// because the scan record carries none.
import type { Scan, ScanList, ScanPort } from "./api";
import { groupPorts } from "./console";
import { fmtSpan } from "./discovery";

// The three statuses a scan holds before it finishes (scan_status enum,
// store/scans.go). The list endpoint filters by ONE status per request, so
// Running Scans asks for each status it shows (SHOWN) separately rather than
// inventing a multi-status filter.
export const IN_FLIGHT = ["pending", "planning", "running"] as const;
export type InFlight = (typeof IN_FLIGHT)[number];

export const IN_FLIGHT_LABEL: Record<InFlight, string> = { pending: "Pending", planning: "Planning", running: "Running" };
// pending → amber, planning → blue, running → green: the console's chips.
export const IN_FLIGHT_CHIP: Record<InFlight, string> = { pending: "warn", planning: "accent", running: "ok" };

export const isInFlight = (s: string): s is InFlight => (IN_FLIGHT as readonly string[]).includes(s);

// The statuses Running Scans shows. Planning is left out on purpose: PlanScan
// moves pending → planning → running in one transaction, so no read ever
// returns it, and a tile or filter for it would only ever say 0.
export const SHOWN = ["pending", "running"] as const;
export type Shown = (typeof SHOWN)[number];

// The page size the list endpoint allows at most.
export const SCAN_PAGE = 200;

// Running Scans shows scans requested in the last 24 hours. Older in-flight
// scans stay where they are on the server; this is a view, not a cleanup.
export const WINDOW_MS = 24 * 60 * 60 * 1000;

// In the window when requested at or after now − 24h: exactly 24 hours ago is
// in, a millisecond earlier is out. created_at is RFC 3339 with an offset, so
// Date.parse compares instants whatever the zone. A request time ahead of the
// browser's clock (skew between it and Core) is in, not hidden; one that does
// not parse is out, because nothing shows it is recent.
export function inWindow(createdAt: string, now: number): boolean {
  const t = Date.parse(createdAt);
  return Number.isFinite(t) && t >= now - WINDOW_MS;
}

// One status's read narrowed to the window, against ONE reference time so the
// tile and the table agree. `more` says the server holds further rows that may
// also be in the window: there is a cursor, and every row on this page is
// still inside it. Pages run newest request first, so once a page reaches a
// row older than the cutoff, every later page is older too and the count is
// exact.
export function windowed(list: ScanList, status: Shown, now: number): { scans: Scan[]; more: boolean } {
  const scans = list.scans.filter((s) => s.status === status && inWindow(s.created_at, now));
  const more = !!list.next_before && list.scans.every((s) => inWindow(s.created_at, now));
  return { scans, more };
}

// "—" for a read that has not answered (loading or failed), never 0.
export function windowCountLabel(w: { scans: Scan[]; more: boolean } | undefined): string {
  if (!w) return "—";
  return w.more ? `${w.scans.length}+` : String(w.scans.length);
}

// requested_by is a user id (absent for a scan Core requested itself). There
// is no route that turns an id into a name, so the console never shows one.
export function requesterLabel(requestedBy: string | null | undefined, sessionUserID: string | undefined): string {
  if (!requestedBy) return "system";
  if (sessionUserID && requestedBy === sessionUserID) return "You";
  return requestedBy.slice(0, 8);
}

// How long a scan has been in its state: waiting since it was requested while
// pending or planning, running since started_at once it runs. A running scan
// with no started_at (none should exist) falls back to its request time rather
// than showing nothing.
export function elapsedLabel(s: Pick<Scan, "status" | "created_at" | "started_at">, now = Date.now()): string {
  if (s.status === "running") return `Running ${fmtSpan(now - new Date(s.started_at ?? s.created_at).getTime())}`;
  return `Waiting ${fmtSpan(now - new Date(s.created_at).getTime())}`;
}

export type RunningFilter = { status: "" | Shown; type: string; policy: string; mine: boolean };

// Narrow the loaded rows. Type, policy and "mine" have no server-side filter,
// so they apply to what the three reads returned; status picks which read.
export function filterScans(rows: Scan[], f: RunningFilter, sessionUserID: string | undefined): Scan[] {
  return rows.filter(
    (s) =>
      (!f.status || s.status === f.status) &&
      (!f.type || s.scan_type === f.type) &&
      (!f.policy || s.policy_id === f.policy) &&
      (!f.mine || (!!sessionUserID && s.requested_by === sessionUserID)),
  );
}

// Newest request first, the order the endpoint itself uses, across the three
// reads merged.
export function newestFirst(rows: Scan[]): Scan[] {
  const t = (s: Scan) => new Date(s.created_at).getTime();
  return [...rows].sort((a, b) => t(b) - t(a) || b.id.localeCompare(a.id));
}

export const distinct = (values: string[]): string[] => [...new Set(values)].sort();

// ---------------------------------------------------------------- drawer
// The View drawer's reading of /v1/scans/{id}/results. Every number here is a
// count of the rows the server returned, nothing more: the rows are NOT
// de-duplicated (one address:port seen twice is two observations), and past
// the server's cap `truncated` says the set is incomplete, so both counts then
// read "N+".
export const DRAWER_HOST_LIMIT = 10;

type ResultRow = Pick<ScanPort, "address" | "port" | "protocol" | "observed_at">;
export type ResultSummary = {
  hosts: string;
  observations: string;
  groups: [string, ResultRow[]][];
  shown: [string, ResultRow[]][];
  more: number;
  latest: string | null;
};

export function summarizeResults(r: { ports: ResultRow[]; hosts: number; truncated: boolean }, limit = DRAWER_HOST_LIMIT): ResultSummary {
  // Grouped across EVERY returned row before the display limit applies, so
  // "+N more" counts hosts, not rows.
  const groups = groupPorts(r.ports, (p) => p.address);
  let latest: string | null = null;
  let latestMs = -Infinity;
  for (const p of r.ports) {
    const ms = new Date(p.observed_at).getTime();
    if (Number.isFinite(ms) && ms > latestMs) {
      latestMs = ms;
      latest = p.observed_at;
    }
  }
  const plus = r.truncated ? "+" : "";
  return {
    hosts: `${r.hosts}${plus}`,
    observations: `${r.ports.length}${plus}`,
    groups,
    shown: groups.slice(0, limit),
    more: Math.max(0, groups.length - limit),
    latest,
  };
}

// "22/TCP, 443/TCP" — one host's ports, ascending as groupPorts leaves them.
export const portList = (rows: ResultRow[]): string => rows.map((p) => `${p.port}/${(p.protocol || "tcp").toUpperCase()}`).join(", ");

// Only the discovery engine records `port` observations
// (internal/engines/discovery/discovery.go is the one observation(taskID,
// "port", …) in internal/engines), so for any other scan type an empty result
// is structural, not "nothing found".
export const RECORDS_PORT_OBSERVATIONS: ReadonlySet<string> = new Set(["discovery"]);

// What an empty, successful results read means for this scan. Never "found
// nothing": zero rows can be pending ingest, aged out, or a type that records
// no ports at all.
export function emptyResultMessage(s: Pick<Scan, "scan_type" | "status">): string {
  if (!RECORDS_PORT_OBSERVATIONS.has(s.scan_type)) return "This scan type records no open-port observations.";
  if (isInFlight(s.status)) return "Nothing observed yet; results appear once accepted by ingest.";
  return "No open-port observations remain (none recorded, or aged out).";
}

// Kill switches that provably cover this scan: one naming it, or a
// tenant-wide one ("halts everything this tenant is running"). A zone-scoped
// kill is never matched — a scan carries no zone, so applicability would be a
// guess.
export function killsFor<K extends { scope: string; scan_id?: string | null }>(scanID: string, kills: K[]): K[] {
  return kills.filter((k) => k.scope === "tenant" || (k.scope === "scan" && k.scan_id === scanID));
}

// The drawer's requester: the full user id where the table shortens it.
export function requesterFull(requestedBy: string | null | undefined, sessionUserID: string | undefined): string {
  if (!requestedBy) return "system";
  if (sessionUserID && requestedBy === sessionUserID) return "You";
  return requestedBy;
}
