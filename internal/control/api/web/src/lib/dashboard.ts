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
  // The category colour, and a darker shade of it: the card's filled tile runs
  // from one to the other behind a white glyph, and the shade keeps that glyph
  // at 3:1 or better in both themes. Every category has its own pair.
  color: string;
  dark: string;
  // Where the card leads. Absent for a category Core does not hold, whose card
  // opens the not-yet-integrated view instead.
  to?: string;
  // Why a category reads "—": the source it would need and does not have.
  gap?: string;
};

export type IconName =
  | "boxes" | "network" | "server" | "laptop" | "plug" | "globe"
  | "container" | "layers" | "database" | "cloud" | "router" | "shapes" | "help";

const NO_DEVICE_TYPE = "Core does not classify assets by device type: the device-type field exists on an asset and nothing writes it.";

// The eleven cards, in their required order. The same entries drive the
// cards, the asset-row icons and types, and the distribution's colours.
export const CATEGORIES: Category[] = [
  { key: "total", label: "Total Assets", type: "Asset", icon: "boxes", color: "#3B82F6", dark: "#2563EB", to: "/discover/discovery/asset-inventory" },
  { key: "ip", label: "IP Addresses", type: "IP Address", icon: "network", color: "#6366F1", dark: "#4F46E5", to: "/discover/discovery/asset-inventory" },
  { key: "servers", label: "Servers", type: "Server", icon: "server", color: "#8B5CF6", dark: "#7C3AED", gap: NO_DEVICE_TYPE },
  { key: "laptops", label: "Laptops", type: "Laptop", icon: "laptop", color: "#84CC16", dark: "#65A30D",
    gap: "Core does not classify assets by device type, and a network scan cannot tell a laptop from any other host." },
  { key: "apis", label: "APIs", type: "API", icon: "plug", color: "#F97316", dark: "#EA580C",
    gap: "Core has no API inventory: no table or route records an API as an asset." },
  { key: "webapps", label: "Web Applications", type: "Web Application", icon: "globe", color: "#10B981", dark: "#059669",
    gap: "Core has no web-application inventory. Web ports are recorded as services on hosts, which are not applications." },
  { key: "docker", label: "Docker Containers", type: "Docker Container", icon: "container", color: "#0EA5E9", dark: "#0284C7",
    gap: "Core does not discover containers." },
  { key: "k8s", label: "Kubernetes Clusters", type: "Kubernetes Cluster", icon: "layers", color: "#D946EF", dark: "#C026D3",
    gap: "Core does not discover Kubernetes clusters." },
  { key: "databases", label: "Databases", type: "Database", icon: "database", color: "#F43F5E", dark: "#E11D48", to: "/discover/discovery/databases" },
  { key: "cloud", label: "Cloud Assets", type: "Cloud Asset", icon: "cloud", color: "#F59E0B", dark: "#D97706",
    gap: "Core does not discover cloud resources." },
  { key: "network", label: "Network Devices", type: "Network Device", icon: "router", color: "#14B8A6", dark: "#0D9488", gap: NO_DEVICE_TYPE },
];

export const categoryByKey = (key: string | undefined): Category | undefined => CATEGORIES.find((c) => c.key === key);

// An asset row whose kind Core has not established.
export const UNKNOWN_KIND = { label: "Unknown", icon: "help" as IconName, color: "#64748B" };

// ---------------------------------------------------------------- counts
// A measured count. `null` means not measured — not integrated, still loading,
// or failed — and renders "—". `assets` is how many ASSETS the category
// covers, which is what its share is taken from; for IP Addresses that differs
// in kind from the count, which is addresses. `atLeast` is a lower bound shown
// only as a hint when a capped read could not count exactly.
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
  return { count: hosts, assets: hosts };
}

export function measure(inv: Inventory): Record<CategoryKey, Measure> {
  const out = Object.fromEntries(CATEGORIES.map((c) => [c.key, { count: null, note: c.gap }])) as Record<CategoryKey, Measure>;
  out.total = { count: inv.assets ? inv.assets.length : null };
  // IP Addresses is a SUBSET of the inventory, not a kind of asset beside it:
  // every live address belongs to one of the assets. Its count is addresses
  // (the presence total); its share is the assets that hold one.
  const addressed = inv.assets ? inv.assets.filter(hasCurrentAddress).length : null;
  out.ip = {
    count: inv.addresses ?? null,
    assets: inv.addresses === undefined ? null : addressed,
    note: inv.addresses !== undefined && addressed !== null
      ? `${inv.addresses.toLocaleString()} live IP address${inv.addresses === 1 ? "" : "es"}, held by ${addressed.toLocaleString()} of the ${inv.assets!.length.toLocaleString()} assets. The share is the assets that hold a current address.`
      : undefined,
  };
  out.databases = databaseHosts(inv.openPorts);
  return out;
}

// A category's share is the assets it covers over the distribution's sum —
// the whole inventory, which the distribution partitions exactly. Total
// Assets IS that sum, so it has no share of its own. Nothing is rounded to
// make shares reach 100; a missing count or denominator is "—".
export function share(c: Category, m: Measure, total: number | null): number | null {
  if (c.key === "total") return null;
  if (total === null || total === 0 || m.count === null || m.assets === null || m.assets === undefined) return null;
  return (100 * m.assets) / total;
}

export function fmtShare(pct: number | null): string {
  if (pct === null) return "—";
  if (pct === 0 || pct === 100) return `${pct}%`;
  // Below 10%, one decimal, so 0.2% does not read as 0%.
  return pct < 10 ? `${pct.toFixed(1)}%` : `${Math.round(pct)}%`;
}

export const fmtCount = (m: Measure): string => (m.count === null ? "—" : m.count.toLocaleString());

export type Segment = { key: string; label: string; color: string; value: number };

// The distribution: the one partition of the inventory Core measures exactly,
// mutually exclusive and exhaustive — assets that hold a current IP address
// and assets that hold none. Its segments always sum to Total Assets. Nothing
// else can join it: a database host may or may not hold an address, so adding
// Databases would count assets twice, and Core classifies no device types. A
// zero segment is left out; an unread inventory draws nothing.
export function distribution(assets: AssetSummary[] | undefined): Segment[] {
  if (!assets) return [];
  const addressed = assets.filter(hasCurrentAddress).length;
  const ip = categoryByKey("ip")!;
  return [
    { key: "addressed", label: "With a current IP address", color: ip.color, value: addressed },
    { key: "unaddressed", label: "No current IP address", color: UNKNOWN_KIND.color, value: assets.length - addressed },
  ].filter((s) => s.value > 0);
}

// The ring's arc lengths. Each non-zero segment is proportional to its value,
// but never shorter than `min`, so a small share stays visible; the length it
// gains comes from the largest segment, and the legend keeps the exact
// numbers. With more than one segment a `gap` separates them.
export function arcs(segs: Segment[], circ: number, min = 6, gap = 2): { key: string; start: number; len: number }[] {
  const total = segs.reduce((n, s) => n + s.value, 0);
  if (total <= 0) return [];
  const g = segs.length > 1 ? gap : 0;
  const raw = segs.map((s) => (s.value / total) * circ);
  const lens = raw.map((l) => Math.max(l, Math.min(min, circ / segs.length)));
  const big = raw.indexOf(Math.max(...raw));
  lens[big] -= lens.reduce((n, l) => n + l, 0) - circ;
  let start = 0;
  return segs.map((s, i) => {
    const a = { key: s.key, start, len: Math.max(0, lens[i] - g) };
    start += lens[i];
    return a;
  });
}

// What a table row may say an asset IS. The device type Core stores, when
// one is set, mapped to the dashboard's own words; otherwise a database host
// (a host where Core identified a database service — the capped open-port read
// can miss one, never invent one); otherwise Unknown. An address alone never
// makes a type.
const DEVICE_TYPES: [RegExp, CategoryKey][] = [
  [/server/i, "servers"], [/laptop|notebook/i, "laptops"], [/router|switch|firewall|access.?point|network/i, "network"],
  [/kubernetes|k8s/i, "k8s"], [/container|docker/i, "docker"], [/database|\bdb\b/i, "databases"],
  [/cloud/i, "cloud"], [/\bapi\b/i, "apis"], [/web.?app/i, "webapps"],
];

export type Kind = { label: string; icon: IconName; color: string; dark?: string; known: boolean };

export function assetKind(a: Pick<AssetSummary, "id" | "device_type">, ports?: { asset_id: string; service?: string | null }[]): Kind {
  const dt = (a.device_type ?? "").trim();
  if (dt) {
    const hit = DEVICE_TYPES.find(([re]) => re.test(dt));
    const c = hit && categoryByKey(hit[1]);
    if (c) return { label: c.type, icon: c.icon, color: c.color, dark: c.dark, known: true };
  }
  if (ports?.some((p) => p.asset_id === a.id && isDatabaseService(p.service))) {
    const db = categoryByKey("databases")!;
    return { label: db.type, icon: db.icon, color: db.color, dark: db.dark, known: true };
  }
  return { ...UNKNOWN_KIND, known: false };
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
