// Pure helpers behind the Security Overview dashboard. No I/O. Every count here
// is one Core served; a category Core holds no data for is `null` and renders
// "—", never 0, and a share is computed only over a denominator that was
// measured completely.
import type { AssetList, AssetSummary, FindingList, FindingSummary, OpenPorts } from "./api";
import { isDatabaseService } from "./discovery";

// ---------------------------------------------------------------- ranges
// The selectable period. It filters only the two "recent" panels; every card,
// share and the distribution are the current inventory, whatever is selected.
export const RANGES = [
  { key: "24h", label: "Last 24 Hours", days: 1 },
  { key: "3d", label: "Last 3 Days", days: 3 },
  { key: "7d", label: "Last 7 Days", days: 7 },
  { key: "15d", label: "Last 15 Days", days: 15 },
  { key: "30d", label: "Last 30 Days", days: 30 },
  { key: "60d", label: "Last 60 Days", days: 60 },
  { key: "90d", label: "Last 90 Days", days: 90 },
] as const;
export type RangeKey = (typeof RANGES)[number]["key"];
export type Range = (typeof RANGES)[number];
export const DEFAULT_RANGE: RangeKey = "24h";

// An unknown or absent ?range= falls back to the default rather than to "all
// time", which no option offers.
export const rangeFor = (key: string | null | undefined): Range => RANGES.find((r) => r.key === key) ?? RANGES[0];

const DAY_MS = 24 * 60 * 60 * 1000;

// In the period when at or after now − days·24h: exactly the boundary is in, a
// millisecond earlier is out. Timestamps are RFC 3339 with an offset, so they
// compare as instants. A time ahead of the browser's clock (skew with Core) is
// in rather than hidden; one that does not parse is out.
export function inRange(iso: string | null | undefined, days: number, now: number): boolean {
  const t = Date.parse(iso ?? "");
  return Number.isFinite(t) && t >= now - days * DAY_MS;
}

// Newest first by a timestamp field, id as the tie-break so the order is stable.
export function newestBy<T extends { id: string }>(rows: T[], at: (r: T) => string): T[] {
  const t = (r: T) => Date.parse(at(r)) || 0;
  return [...rows].sort((a, b) => t(b) - t(a) || b.id.localeCompare(a.id));
}

// ---------------------------------------------------------------- categories
export type CategoryKey =
  | "total" | "ip" | "servers" | "laptops" | "apis" | "webapps"
  | "docker" | "k8s" | "databases" | "cloud" | "network" | "other";

export type Category = {
  key: CategoryKey;
  label: string;
  // The singular form a table row uses for an asset of this kind.
  type: string;
  icon: IconName;
  // The category colour (its 500 shade) and a deeper shade of it (700). The
  // icon tile is a light tint of the colour; the glyph on it is the colour
  // itself on the dark theme and the deeper shade on the light one, which keeps
  // it at 3:1 or better against its tile in both. Every category has its own.
  color: string;
  deep: string;
  // Where the card leads. Absent for a category Core does not hold, whose card
  // opens the not-yet-integrated view instead.
  to?: string;
  // Why a category reads "—": the source it would need and does not have.
  gap?: string;
};

export type IconName =
  | "boxes" | "network" | "server" | "laptop" | "plug" | "globe"
  | "container" | "layers" | "database" | "cloud" | "router" | "shapes" | "help";

const NO_DEVICE_TYPE = "Core does not classify assets by device type yet: the device-type field exists on an asset and nothing writes it. The count appears here once it does.";

// The eleven cards, in their required order. The same entries drive the
// cards, the distribution's segments and legend, and the asset-row icons.
export const CATEGORIES: Category[] = [
  { key: "total", label: "Total Assets", type: "Asset", icon: "boxes", color: "#3B82F6", deep: "#1D4ED8", to: "/discover/discovery/asset-inventory" },
  { key: "ip", label: "IP Addresses", type: "IP Address", icon: "network", color: "#6366F1", deep: "#4338CA", to: "/discover/discovery/asset-inventory" },
  { key: "servers", label: "Servers", type: "Server", icon: "server", color: "#8B5CF6", deep: "#6D28D9", gap: NO_DEVICE_TYPE },
  { key: "laptops", label: "Laptops", type: "Laptop", icon: "laptop", color: "#84CC16", deep: "#4D7C0F", gap: NO_DEVICE_TYPE },
  { key: "apis", label: "APIs", type: "API", icon: "plug", color: "#F97316", deep: "#C2410C",
    gap: "Core has no API inventory: no table or route records an API as an asset." },
  { key: "webapps", label: "Web Applications", type: "Web Application", icon: "globe", color: "#10B981", deep: "#047857",
    gap: "Core has no web-application inventory. Web ports are recorded as services on hosts, which are not applications." },
  { key: "docker", label: "Docker Containers", type: "Docker Container", icon: "container", color: "#0EA5E9", deep: "#0369A1",
    gap: "Core does not discover containers." },
  { key: "k8s", label: "Kubernetes Clusters", type: "Kubernetes Cluster", icon: "layers", color: "#D946EF", deep: "#A21CAF",
    gap: "Core does not discover Kubernetes clusters." },
  { key: "databases", label: "Databases", type: "Database", icon: "database", color: "#F43F5E", deep: "#BE123C", to: "/discover/discovery/databases" },
  { key: "cloud", label: "Cloud Assets", type: "Cloud Asset", icon: "cloud", color: "#F59E0B", deep: "#B45309",
    gap: "Core does not discover cloud resources." },
  { key: "network", label: "Network Devices", type: "Network Device", icon: "router", color: "#14B8A6", deep: "#0F766E", gap: NO_DEVICE_TYPE },
];

export const categoryByKey = (key: string | undefined): Category | undefined => CATEGORIES.find((c) => c.key === key);

// The kinds an asset can be: every category except the two that are not kinds
// of asset — Total Assets is the whole and IP Addresses a property (an asset
// HAS an address; it is not one).
export const KIND_KEYS = CATEGORIES.filter((c) => c.key !== "total" && c.key !== "ip").map((c) => c.key);

// An asset whose kind Core has not established.
export const UNKNOWN_KIND = { label: "Unknown", icon: "help" as IconName, color: "#64748B", deep: "#475569" };
// The distribution's remainder: assets measured as none of the kinds.
export const UNCLASSIFIED = { key: "unclassified", label: "Unclassified", color: "#64748B" };

// ---------------------------------------------------------------- kinds
// What one asset IS — at most one kind, so no asset is counted twice. The
// device type Core stores, when one is set, mapped to the dashboard's words;
// otherwise a database host (Core identified a database service on it);
// otherwise none. An address alone never makes a kind.
const DEVICE_TYPES: [RegExp, CategoryKey][] = [
  [/server/i, "servers"], [/laptop|notebook/i, "laptops"], [/router|switch|firewall|access.?point|network/i, "network"],
  [/kubernetes|k8s/i, "k8s"], [/container|docker/i, "docker"], [/database|\bdb\b/i, "databases"],
  [/cloud/i, "cloud"], [/\bapi\b/i, "apis"], [/web.?app/i, "webapps"],
];

type PortRow = { asset_id: string; service?: string | null };

export function kindKey(a: Pick<AssetSummary, "id" | "device_type">, ports?: PortRow[]): CategoryKey | null {
  const dt = (a.device_type ?? "").trim();
  const hit = dt ? DEVICE_TYPES.find(([re]) => re.test(dt)) : undefined;
  if (hit) return hit[1];
  if (ports?.some((p) => p.asset_id === a.id && isDatabaseService(p.service))) return "databases";
  return null;
}

export type Kind = { label: string; icon: IconName; color: string; deep: string; known: boolean };

export function assetKind(a: Pick<AssetSummary, "id" | "device_type">, ports?: PortRow[]): Kind {
  const c = categoryByKey(kindKey(a, ports) ?? undefined);
  return c ? { label: c.type, icon: c.icon, color: c.color, deep: c.deep, known: true } : { ...UNKNOWN_KIND, known: false };
}

// ---------------------------------------------------------------- counts
// A measured count. `null` means not measured — not integrated, still loading,
// or failed — and renders "—". `assets` is how many ASSETS the figure covers,
// which is what its share is taken from; for IP Addresses that differs in kind
// from the count, which is addresses. `atLeast` is a lower bound shown only as
// a hint when a capped read could not count exactly.
export type Measure = { count: number | null; assets?: number | null; atLeast?: number; note?: string };

export type Inventory = {
  // Every asset, read to the last page. Undefined until that completed.
  assets?: AssetSummary[];
  // Live addresses, from the presence composition the asset list carries.
  addresses?: number;
  openPorts?: OpenPorts;
};

// An asset row carries `address` exactly when the asset holds a current IP
// address (the earliest one; store.Assets.List), whatever its hostname.
export const hasCurrentAddress = (a: Pick<AssetSummary, "address">): boolean => !!a.address;

export type Measures = Record<CategoryKey, Measure> & { unclassified: Measure };

// Every card's figure, and the remainder, from one pass that gives each asset
// at most one kind. Which figures are MEASURED:
//  - Total Assets and IP Addresses, once the inventory is read;
//  - the device-type kinds, once Core stores a device type on any asset —
//    until then a count of 0 would claim a classification never made;
//  - Databases, while the open-port read is complete. Past its cap a database
//    host can be missed, so Databases — and the remainder that would silently
//    absorb the missed ones — read "—", with the lower bound as a hint.
// APIs, web applications, containers, clusters and cloud assets are counted
// from a device type too, the only source Core could carry them in.
export function measure(inv: Inventory): Measures {
  const out = Object.fromEntries(CATEGORIES.map((c) => [c.key, { count: null, note: c.gap }])) as unknown as Measures;
  out.unclassified = { count: null };
  const assets = inv.assets;
  if (!assets) {
    out.ip = { count: null };
    return out;
  }
  const total = assets.length;
  out.total = { count: total, assets: total };

  // IP Addresses is a SUBSET of the inventory, not a kind beside it: every live
  // address belongs to one of the assets. Its count is addresses (the presence
  // total); its share is the assets that hold one.
  const addressed = assets.filter(hasCurrentAddress).length;
  out.ip = {
    count: inv.addresses ?? null,
    assets: inv.addresses === undefined ? null : addressed,
    note: inv.addresses !== undefined
      ? `${inv.addresses.toLocaleString()} live IP address${inv.addresses === 1 ? "" : "es"}, held by ${addressed.toLocaleString()} of the ${total.toLocaleString()} assets. IP Addresses overlaps every kind, so it is not a segment; its share is the assets that hold one.`
      : undefined,
  };

  const ports = inv.openPorts;
  const portsExact = !!ports && !ports.truncated;
  const counts = Object.fromEntries(KIND_KEYS.map((k) => [k, 0])) as Record<CategoryKey, number>;
  let none = 0;
  for (const a of assets) {
    const k = kindKey(a, ports?.ports);
    if (k) counts[k]++;
    else none++;
  }
  const typed = assets.some((a) => !!(a.device_type ?? "").trim());
  for (const k of KIND_KEYS) {
    if (k === "databases") continue;
    if (typed) out[k] = { count: counts[k], assets: counts[k] };
  }
  if (!ports) out.databases = { count: null };
  else if (portsExact) out.databases = { count: counts.databases, assets: counts.databases };
  else out.databases = { count: null, atLeast: counts.databases, note: `At least ${counts.databases} — Core lists only the ${ports.limit} most recently seen open ports, so the exact count cannot be read.` };

  // The remainder is exact only when every kind that can absorb an asset was
  // measured exactly. Unmeasured device-type kinds hold nothing (no asset has
  // a device type), so they cannot hide one.
  if (portsExact) out.unclassified = { count: none, assets: none };
  return out;
}

// A share is the assets a figure covers over the distribution's sum — the
// whole inventory, which the segments partition, each asset in at most one.
// Total Assets' share is how much of the inventory is CLASSIFIED (the kinds'
// sum over the total), not a 100% of itself; it needs the remainder measured.
// Nothing is rounded to make shares reach 100; a missing count or a zero
// denominator is "—".
export function share(key: CategoryKey | "unclassified", ms: Measures): number | null {
  const total = ms.total.count;
  if (total === null || total === 0) return null;
  if (key === "total") {
    const rest = ms.unclassified.count;
    return rest === null ? null : (100 * (total - rest)) / total;
  }
  const m = ms[key];
  if (m.count === null || m.assets === null || m.assets === undefined) return null;
  return (100 * m.assets) / total;
}

export function fmtShare(pct: number | null): string {
  if (pct === null) return "—";
  if (pct === 0 || pct === 100) return `${pct}%`;
  // Rounding must never claim all or none of the inventory when it is
  // neither: a share above 0 never reads 0%, one below 100 never reads 100%.
  if (pct < 0.1) return "<0.1%";
  if (pct > 99.9) return ">99.9%";
  if (pct < 10) return `${pct.toFixed(1)}%`;
  if (pct >= 99.5) return `${(Math.floor(pct * 10) / 10).toFixed(1)}%`;
  return `${Math.round(pct)}%`;
}

export const fmtCount = (m: Measure): string => (m.count === null ? "—" : m.count.toLocaleString());

export type Segment = { key: string; label: string; color: string; value: number };

// The distribution's segments: every measured kind with assets, in card
// order and colour, then the Unclassified remainder when it was measured. The
// kinds are mutually exclusive by construction, so when every one is measured
// the segments sum exactly to Total Assets; an unmeasured kind leaves its part
// of the ring undrawn rather than borrowed by another.
export function distribution(ms: Measures): Segment[] {
  if (ms.total.count === null) return [];
  const segs: Segment[] = CATEGORIES.filter((c) => KIND_KEYS.includes(c.key) && (ms[c.key].count ?? 0) > 0)
    .map((c) => ({ key: c.key, label: c.label, color: c.color, value: ms[c.key].count! }));
  if ((ms.unclassified.count ?? 0) > 0) segs.push({ key: UNCLASSIFIED.key, label: UNCLASSIFIED.label, color: UNCLASSIFIED.color, value: ms.unclassified.count! });
  return segs;
}

// The ring's arcs, each a fraction of the WHOLE inventory (not of the drawn
// segments, so an unmeasured part stays empty). A non-zero segment is never
// shorter than `min` so it stays visible; the length it gains comes from the
// largest segment, never from empty track, and the legend keeps the exact
// numbers. Adjacent segments are separated by `gap`.
export function arcs(segs: Segment[], total: number, circ: number, min = 4, gap = 2): { key: string; start: number; len: number }[] {
  if (total <= 0) return [];
  const live = segs.filter((s) => s.value > 0);
  if (!live.length) return [];
  const g = live.length > 1 ? gap : 0;
  const raw = live.map((s) => (s.value / total) * circ);
  const lens = raw.map((l) => Math.max(l, min + g));
  const big = raw.indexOf(Math.max(...raw));
  lens[big] = Math.max(min + g, lens[big] - (lens.reduce((n, l) => n + l, 0) - raw.reduce((n, l) => n + l, 0)));
  let start = 0;
  return live.map((s, i) => {
    const a = { key: s.key, start, len: Math.max(0, lens[i] - g) };
    start += lens[i];
    return a;
  });
}

// ---------------------------------------------------------------- paging
// Read a keyset-paged list to the end. A dashboard count is exact only over
// every page, so a failed page fails the whole read rather than leaving a
// partial number that looks like a total. The page bound keeps a runaway
// cursor from looping; reaching it is an error, not a truncated answer.
export const MAX_PAGES = 100;

export async function allAssets(list: (q: string) => Promise<AssetList>, limit = 200): Promise<{ assets: AssetSummary[]; addresses: number | undefined }> {
  const out: AssetSummary[] = [];
  let addresses: number | undefined;
  let cursor = "";
  for (let i = 0; i < MAX_PAGES; i++) {
    const page = await list(`?limit=${limit}${cursor}`);
    if (i === 0) addresses = page.address_presence?.total;
    out.push(...page.assets);
    if (!page.next_before || !page.next_id) return { assets: out, addresses };
    cursor = `&before=${encodeURIComponent(page.next_before)}&before_id=${encodeURIComponent(page.next_id)}`;
  }
  throw new Error(`more than ${MAX_PAGES * limit} assets; the dashboard cannot count them exactly`);
}

export async function allFindings(list: (q: string) => Promise<FindingList>, limit = 200): Promise<FindingSummary[]> {
  const out: FindingSummary[] = [];
  let cursor = "";
  for (let i = 0; i < MAX_PAGES; i++) {
    const page = await list(`?limit=${limit}${cursor}`);
    out.push(...page.findings);
    if (!page.next_score || !page.next_id) return out;
    cursor = `&before_score=${encodeURIComponent(page.next_score)}&before_id=${encodeURIComponent(page.next_id)}`;
  }
  throw new Error(`more than ${MAX_PAGES * limit} findings; the dashboard cannot filter them exactly`);
}

// Severity colours for the findings panel; the dot carries the colour and the
// word carries the meaning.
export const SEVERITY_COLOR: Record<string, string> = {
  critical: "#EF4444", high: "#F97316", medium: "#FACC15", low: "#3B82F6", info: "#94A3B8",
};
export const SEVERITY_LABEL: Record<string, string> = {
  critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Informational",
};

// Search over the complete finding set: rule, CVE, category and asset name,
// case-insensitive. The finding list has no server-side text filter.
export function matchFinding(f: FindingSummary, q: string): boolean {
  const needle = q.trim().toLowerCase();
  if (!needle) return false;
  return [f.rule, f.cve, f.category, f.asset_hostname, f.asset_id, f.instance_locator].some((v) => !!v && v.toLowerCase().includes(needle));
}
