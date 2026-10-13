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
  icon: IconName;
  color: string;
  // A slice is a kind of asset: one share of the inventory, drawn in the
  // distribution. Total Assets is the whole, and IP Addresses counts
  // addresses rather than assets, so neither is a slice.
  slice: boolean;
  // Where the card leads. Absent for a category Core does not hold, whose card
  // opens the not-yet-integrated view instead.
  to?: string;
  // Why a category reads "—": the source it would need and does not have.
  gap?: string;
};

export type IconName =
  | "boxes" | "network" | "server" | "laptop" | "plug" | "globe"
  | "container" | "layers" | "database" | "cloud" | "router" | "shapes";

// The twelve cards, in their required order. The same entries drive the
// cards, the distribution legend and the asset-row icons.
export const CATEGORIES: Category[] = [
  { key: "total", label: "Total Assets", icon: "boxes", color: "#3B82F6", slice: false, to: "/discover/discovery/asset-inventory" },
  { key: "ip", label: "IP Addresses", icon: "network", color: "#3B82F6", slice: false, to: "/discover/discovery/asset-inventory" },
  { key: "servers", label: "Servers", icon: "server", color: "#8B5CF6", slice: true,
    gap: "Core does not classify assets by device type: the device-type field exists on an asset and nothing writes it." },
  { key: "laptops", label: "Laptops", icon: "laptop", color: "#10B981", slice: true,
    gap: "Core does not classify assets by device type, and a network scan cannot tell a laptop from any other host." },
  { key: "apis", label: "APIs", icon: "plug", color: "#F97316", slice: true,
    gap: "Core has no API inventory: no table or route records an API as an asset." },
  { key: "webapps", label: "Web Applications", icon: "globe", color: "#10B981", slice: true,
    gap: "Core has no web-application inventory. Web ports are recorded as services on hosts, which are not applications." },
  { key: "docker", label: "Docker Containers", icon: "container", color: "#3B82F6", slice: true,
    gap: "Core does not discover containers." },
  { key: "k8s", label: "Kubernetes Clusters", icon: "layers", color: "#8B5CF6", slice: true,
    gap: "Core does not discover Kubernetes clusters." },
  { key: "databases", label: "Databases", icon: "database", color: "#F43F5E", slice: true, to: "/discover/discovery/databases" },
  { key: "cloud", label: "Cloud Assets", icon: "cloud", color: "#F59E0B", slice: true,
    gap: "Core does not discover cloud resources." },
  { key: "network", label: "Network Devices", icon: "router", color: "#06B6D4", slice: true,
    gap: "Core does not classify assets by device type: the device-type field exists on an asset and nothing writes it." },
  { key: "other", label: "Other Assets", icon: "shapes", color: "#94A3B8", slice: true,
    gap: "Other is what remains once every asset is classified. Core classifies none, so no remainder can be measured." },
];

export const categoryByKey = (key: string | undefined): Category | undefined => CATEGORIES.find((c) => c.key === key);

// The colour and icon for an asset nobody classified: the distribution's
// Unclassified segment and an asset row with no known kind.
export const UNCLASSIFIED = { label: "Unclassified", icon: "shapes" as IconName, color: "#64748B" };

// ---------------------------------------------------------------- counts
// A measured count. `null` means not measured — not integrated, still loading,
// or failed — and renders "—". `atLeast` is a lower bound shown only as a
// hint when a capped read could not count exactly.
export type Measure = { count: number | null; atLeast?: number; note?: string };

export type Inventory = {
  // Every asset, read to the last page. Undefined until that completed.
  assets?: AssetSummary[];
  // Live addresses, from the presence composition the asset list carries.
  addresses?: number;
  openPorts?: OpenPorts;
};

// Hosts carrying a database service Core identified (MySQL/MariaDB,
// PostgreSQL, SQL Server). It counts HOSTS, not services or ports: one host
// with two engines is one. The open-port read is capped, so past the cap the
// count is only a lower bound and the card reads "—".
export function databaseHosts(ports: OpenPorts | undefined): Measure {
  if (!ports) return { count: null };
  const hosts = new Set(ports.ports.filter((p) => isDatabaseService(p.service)).map((p) => p.asset_id)).size;
  if (ports.truncated) {
    return { count: null, atLeast: hosts, note: `At least ${hosts} — Core lists only the ${ports.limit} most recently seen open ports, so the exact count cannot be read.` };
  }
  return { count: hosts };
}

export function measure(inv: Inventory): Record<CategoryKey, Measure> {
  const out = Object.fromEntries(CATEGORIES.map((c) => [c.key, { count: null, note: c.gap }])) as Record<CategoryKey, Measure>;
  out.total = { count: inv.assets ? inv.assets.length : null };
  out.ip = { count: inv.addresses ?? null };
  out.databases = databaseHosts(inv.openPorts);
  return out;
}

// Category share: count ÷ the whole inventory × 100. Only a slice has a share
// (and Total Assets is its own whole, 100%). Nothing is rounded to make the
// shares sum to 100; a missing count or denominator is "—".
export function share(c: Category, m: Measure, total: number | null): number | null {
  if (total === null || total === 0 || m.count === null) return null;
  if (c.key === "total") return 100;
  if (!c.slice) return null;
  return (100 * m.count) / total;
}

export function fmtShare(pct: number | null): string {
  if (pct === null) return "—";
  if (pct === 0 || pct === 100) return `${pct}%`;
  // Below 10%, one decimal, so 0.2% does not read as 0%.
  return pct < 10 ? `${pct.toFixed(1)}%` : `${Math.round(pct)}%`;
}

export const fmtCount = (m: Measure): string => (m.count === null ? "—" : m.count.toLocaleString());

// The distribution's segments: every slice measured exactly, and the
// Unclassified remainder only when every slice was measured — otherwise the
// remainder would silently absorb the unmeasured ones.
export function distribution(ms: Record<CategoryKey, Measure>, total: number | null): { key: string; label: string; color: string; value: number }[] {
  if (total === null) return [];
  const slices = CATEGORIES.filter((c) => c.slice);
  const measured = slices.filter((c) => ms[c.key].count !== null)
    .map((c): { key: string; label: string; color: string; value: number } => ({ key: c.key, label: c.label, color: c.color, value: ms[c.key].count! }));
  const segs = measured.filter((s) => s.value > 0);
  if (measured.length === slices.length) {
    const rest = total - measured.reduce((n, s) => n + s.value, 0);
    if (rest > 0) segs.push({ key: "unclassified", label: UNCLASSIFIED.label, color: UNCLASSIFIED.color, value: rest });
  }
  return segs;
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
