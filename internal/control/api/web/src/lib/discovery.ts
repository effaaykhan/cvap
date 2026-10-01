// Pure helpers behind the Discover pages. No I/O except fetchAllAssets, which
// only pages a read the server already serves. Every classification here is
// keyed to something Core records — a service name a rule emits, a port a
// probe targets, an identification method — never to a guess about what a
// number "probably" means.
import type { AssetList, AssetSummary, OpenPort } from "./api";
import { isSeenOnly } from "./console";

// ---------------------------------------------------------------- assets

// /v1/assets pages 200 at a time by keyset. The Discover inventory needs the
// whole estate for its counts, so it walks the cursor — up to a cap, and the
// caller says when the cap was hit rather than presenting a partial count as
// the total.
export const ASSET_PAGE = 200;
export const ASSET_CAP = 2000;

export type AllAssets = { assets: AssetSummary[]; complete: boolean; presence: AssetList["address_presence"] };

export async function fetchAllAssets(list: (q: string) => Promise<AssetList>, cap = ASSET_CAP): Promise<AllAssets> {
  const assets: AssetSummary[] = [];
  let presence: AssetList["address_presence"];
  let cursor: { before: string; id: string } | null = null;
  for (;;) {
    const qs = new URLSearchParams({ sort: "last_seen", limit: String(ASSET_PAGE) });
    if (cursor) {
      qs.set("before", cursor.before);
      qs.set("before_id", cursor.id);
    }
    const page = await list(`?${qs}`);
    presence ??= page.address_presence;
    assets.push(...page.assets);
    if (!page.next_before || !page.next_id) return { assets, complete: true, presence };
    if (assets.length >= cap) return { assets, complete: false, presence };
    cursor = { before: page.next_before, id: page.next_id };
  }
}

// What the console calls an asset when it has no name. Hostnames are not
// collected today and an address is only shown while one is CURRENT, so an
// asset can legitimately have neither; its id is then the honest label.
export function assetLabel(a: { id?: string; asset_id?: string; hostname?: string | null; address?: string | null }): string {
  return a.hostname || a.address || (a.id ?? a.asset_id ?? "").slice(0, 8);
}

// ---------------------------------------------------------------- ports

// Three states a listening port can be in, from what Core recorded about it.
// The API's `identified` flag is false only for a port discovery SAW answer
// (method 'discovery'); a port a fingerprint probe touched and learned nothing
// from (method 'none') is "identified" there but carries no service. Splitting
// them keeps "nobody looked" apart from "somebody looked and got nothing".
export type PortState = "recognised" | "probed" | "answered";

export const PORT_STATES: Record<PortState, { label: string; tone: string; why: string }> = {
  recognised: { label: "service recognised", tone: "ok", why: "a banner or probe identified the service listening here" },
  answered: { label: "open, unidentified", tone: "warn", why: "a discovery scan saw the port answer; nothing has identified what is listening" },
  probed: { label: "probed, no match", tone: "muted", why: "a fingerprint attempt reached the port and no rule matched its response" },
};
export const PORT_STATE_ORDER: PortState[] = ["recognised", "answered", "probed"];

export function portState(p: Pick<OpenPort, "identified" | "service">): PortState {
  if (!p.identified) return "answered";
  return p.service ? "recognised" : "probed";
}

// The same three states from an asset-detail service row, which carries the
// identification method rather than the flag.
export function serviceState(s: { method?: string | null; service?: string | null }): PortState {
  if (isSeenOnly(s.method)) return "answered";
  return s.service ? "recognised" : "probed";
}

export function countBy<T, K extends string>(rows: T[], key: (r: T) => K): Record<K, number> {
  const out = {} as Record<K, number>;
  for (const r of rows) {
    const k = key(r);
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}

// Top-N of a tally, largest first, ties by key so the order is stable.
export function topN(tally: Record<string, number>, n: number): [string, number][] {
  return Object.entries(tally)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0], undefined, { numeric: true }))
    .slice(0, n);
}

// ---------------------------------------------------------------- databases

// The database engines Core's rules can name, keyed by the service name the
// rule emits (internal/scanpoint banners.go and probes.go). `ports` are the
// ports the identifying probe targets — or, for MySQL, whose banner arrives on
// any connect, the engine's registered port. An engine absent from this table
// is one no rule identifies, and the Databases page does not claim it.
export const DB_ENGINES: Record<string, { label: string; short: string; ports: number[]; how: string }> = {
  mysql: { label: "MySQL / MariaDB", short: "MySQL", ports: [3306], how: "handshake banner — safe mode" },
  postgresql: { label: "PostgreSQL", short: "PostgreSQL", ports: [5432, 5433, 6432], how: "startup probe — intrusive mode" },
  "ms-sql-s": { label: "Microsoft SQL Server", short: "SQL Server", ports: [1433, 1434], how: "pre-login probe — intrusive mode" },
};

export const isDatabaseService = (service?: string | null) => !!service && service in DB_ENGINES;

// The engine whose identifying port this is, if any.
export function dbEngineForPort(port: number): string | undefined {
  return Object.keys(DB_ENGINES).find((k) => DB_ENGINES[k].ports.includes(port));
}

// ---------------------------------------------------------------- web

// Ports the HTTP and HTTPS HEAD probes target (probes.go: http-head,
// https-head). HTTP never volunteers a banner, so on these ports the probe is
// the only identification Core has — and it runs in intrusive mode only.
export const HTTP_PROBE_PORTS = [80, 81, 88, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8888];
export const HTTPS_PROBE_PORTS = [443, 4443, 8443, 9443, 10443];
export const WEB_PROBE_PORTS = [...HTTP_PROBE_PORTS, ...HTTPS_PROBE_PORTS];

export const isHttpService = (service?: string | null) => service === "http";

// ---------------------------------------------------------------- time

// Local calendar day, so a chart's bars match the dates the tables print.
export function dayKey(iso: string): string {
  const d = new Date(iso);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

// A continuous run of days from the first to the last date seen (at most
// `maxDays`, the most recent kept), each with its count — gaps are zero bars,
// not missing ones, so the axis is honest about quiet days.
export function perDay(dates: string[], maxDays = 60): { day: string; n: number }[] {
  if (dates.length === 0) return [];
  const tally = countBy(dates, dayKey);
  const keys = Object.keys(tally).sort();
  const out: { day: string; n: number }[] = [];
  const end = new Date(`${keys[keys.length - 1]}T00:00:00`);
  const start = new Date(`${keys[0]}T00:00:00`);
  for (let d = new Date(end); d >= start && out.length < maxDays; d.setDate(d.getDate() - 1)) {
    const k = dayKey(d.toISOString());
    out.push({ day: k, n: tally[k] ?? 0 });
  }
  return out.reverse();
}

export type Recency = "day" | "week" | "month" | "older";
export const RECENCY: Record<Recency, { label: string; tone: string }> = {
  day: { label: "last 24 hours", tone: "ok" },
  week: { label: "1–7 days", tone: "accent" },
  month: { label: "7–30 days", tone: "warn" },
  older: { label: "over 30 days", tone: "muted" },
};
export const RECENCY_ORDER: Recency[] = ["day", "week", "month", "older"];

export function recency(iso: string, now = Date.now()): Recency {
  const h = (now - new Date(iso).getTime()) / 3_600_000;
  return h <= 24 ? "day" : h <= 24 * 7 ? "week" : h <= 24 * 30 ? "month" : "older";
}

// Wall-clock length of a scan, from the server's own timestamps. A scan with
// no start has no duration; one still running is measured to now and the
// caller marks it as running.
export function duration(start?: string | null, end?: string | null, now = Date.now()): string {
  if (!start) return "—";
  return fmtSpan((end ? new Date(end).getTime() : now) - new Date(start).getTime());
}

export function fmtSpan(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return "—";
  const m = Math.round(ms / 60_000);
  if (m < 1) return `${Math.max(1, Math.round(ms / 1000))}s`;
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}h ${m % 60}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}

// One formatter, built once: toLocaleString with options builds a new
// Intl.DateTimeFormat on every call, which is measurable on a table that
// re-renders as its rows' detail reads arrive.
const SHORT_DATE = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
const SHORT_DAY = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" });

export function shortDate(iso?: string | null): string {
  return iso ? SHORT_DATE.format(new Date(iso)) : "—";
}

export function shortDay(iso?: string | null): string {
  if (!iso) return "—";
  return SHORT_DAY.format(new Date(/^\d{4}-\d{2}-\d{2}$/.test(iso) ? `${iso}T00:00:00` : iso));
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}
