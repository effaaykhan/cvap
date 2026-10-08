// Pure helpers behind the Running Scans page. No I/O. Every value here comes
// from a field /v1/scans serves (ScanResponse); nothing estimates progress,
// because the scan record carries none.
import type { Scan, ScanList } from "./api";
import { fmtSpan } from "./discovery";

// The three statuses a scan holds before it finishes (scan_status enum,
// store/scans.go). The list endpoint filters by ONE status per request, so the
// page asks for each separately rather than inventing a multi-status filter.
export const IN_FLIGHT = ["pending", "planning", "running"] as const;
export type InFlight = (typeof IN_FLIGHT)[number];

export const IN_FLIGHT_LABEL: Record<InFlight, string> = { pending: "Pending", planning: "Planning", running: "Running" };
// pending → amber, planning → blue, running → green: the console's chips.
export const IN_FLIGHT_CHIP: Record<InFlight, string> = { pending: "warn", planning: "accent", running: "ok" };

export const isInFlight = (s: string): s is InFlight => (IN_FLIGHT as readonly string[]).includes(s);

// The page size the list endpoint allows at most.
export const SCAN_PAGE = 200;

// A count over one page is exact only when the server handed back no cursor;
// otherwise it is "at least", and says so.
export function countLabel(list: ScanList | undefined): string {
  if (!list) return "—";
  return list.next_before ? `${list.scans.length}+` : String(list.scans.length);
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

export type RunningFilter = { status: "" | InFlight; type: string; policy: string; mine: boolean };

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
