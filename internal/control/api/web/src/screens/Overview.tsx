import { Link, useSearchParams } from "react-router-dom";
import { has } from "../lib/api";
import { useAuth } from "../lib/auth";
import { IconTile } from "../components/CategoryIcon";
import { RangePicker } from "../components/RangePicker";
import {
  arcs, CATEGORIES, distribution, fmtCount, fmtShare, inRange, measure, newestBy, rangeFor, RANGES, share,
  type Category, type CategoryKey, type Measure, type Range, type Segment,
} from "../lib/dashboard";
import { AssetTable, FindingTable, useAllFindings, useInventory } from "./DashboardViews";

// Security Overview: the operator landing. The eleven cards, their shares and
// the distribution are the CURRENT inventory and ignore the selected period;
// the period filters only the two recent panels, by each record's own
// first_seen. Every number is read from Core. A category Core holds no data
// for keeps its card and reads "—", and so does anything still loading or
// failed — a 0 is shown only when Core measured zero.
const RECENT_ROWS = 5;

export function Overview() {
  const { session } = useAuth();
  const canAssets = has(session, "asset.read");
  const canFindings = has(session, "finding.read");
  const [params, setParams] = useSearchParams();
  const range = rangeFor(params.get("range"));

  const inv = useInventory(canAssets);
  const findings = useAllFindings(canFindings);
  const now = Date.now();

  const ms = measure({ assets: inv.assets.data?.assets, addresses: inv.assets.data?.addresses, openPorts: inv.ports.data });
  const total = ms.total.count;

  const setRange = (key: string) => {
    const next = new URLSearchParams(params);
    next.set("range", key);
    setParams(next, { replace: true });
  };

  return (
    <section className="so">
      <div className="so-head">
        <h1 className="so-title">Security Overview</h1>
        <RangePicker options={RANGES} value={range.key} onChange={setRange} />
      </div>
      <p className="so-sub">Real-time visibility of your assets, security posture, and application security across your environment.</p>

      {!canAssets && <p className="muted small so-status">This account cannot read assets (it lacks the asset.read permission), so every count reads —.</p>}
      {canAssets && inv.assets.isLoading && <p className="muted small so-status">Loading the asset inventory…</p>}
      {canAssets && inv.assets.error && <p className="error small so-status">Could not load the asset inventory, so its counts read —.</p>}

      <div className="so-cards" aria-label="Asset categories">
        {CATEGORIES.map((c) => <CategoryCard key={c.key} c={c} m={ms[c.key]} total={total} />)}
      </div>

      <div className="so-row">
        <Distribution segs={distribution(inv.assets.data?.assets)} ms={ms} total={total} />
        <div className="card so-panel so-map" aria-label="Asset Map">
          <div className="so-panel-head"><h2>Asset Map</h2></div>
          <div className="so-map-body" />
        </div>
      </div>

      <div className="so-row">
        <RecentAssets range={range} now={now} can={canAssets} q={inv} />
        <RecentFindings range={range} now={now} can={canFindings} q={findings} />
      </div>
    </section>
  );
}

function CategoryCard({ c, m, total }: { c: Category; m: Measure; total: number | null }) {
  const pct = share(c, m, total);
  const integrated = !!c.to;
  const title = !integrated ? `Not yet integrated. ${c.gap ?? ""}`.trim()
    : c.key === "total" ? "Every asset Core holds. Each card's share is taken over this total, so it has none of its own."
    : m.note;
  return (
    <Link className={`card so-card${integrated ? "" : " so-card-gap"}`} to={c.to ?? `/dashboard/categories/${c.key}`} title={title}
          data-category={c.key} aria-label={`${c.label}: ${fmtCount(m)}${integrated ? "" : ", not yet integrated"}`}>
      <span className="so-card-icon"><IconTile name={c.icon} color={c.color} dark={c.dark} /></span>
      <span className="so-card-name">{c.label}</span>
      <span className="so-card-count">{fmtCount(m)}</span>
      <span className="so-card-share">{fmtShare(pct)}</span>
    </Link>
  );
}

// The distribution: the inventory split by whether an asset holds a current
// IP address — the one partition Core measures exactly, so the segments sum
// to the centre total and no asset is counted twice. Segment colours match the
// legend and the IP Addresses card. Categories Core cannot measure are named
// under the legend rather than drawn.
function Distribution({ segs, ms, total }: { segs: Segment[]; ms: Record<CategoryKey, Measure>; total: number | null }) {
  const size = 168, thick = 20, r = (size - thick) / 2, circ = 2 * Math.PI * r;
  const drawn = total !== null && total > 0 ? arcs(segs, circ) : [];
  const unmeasured = CATEGORIES.filter((c) => c.key !== "total" && c.key !== "ip" && ms[c.key].count === null);
  return (
    <div className="card so-panel so-dist" aria-label="Asset Distribution">
      <div className="so-panel-head"><h2>Asset Distribution</h2><span className="so-aside">current inventory</span></div>
      <div className="so-dist-body">
        <svg className="so-ring" viewBox={`0 0 ${size} ${size}`} width={size} height={size} role="img"
             aria-label={segs.length ? segs.map((s) => `${s.label} ${s.value}`).join(", ") : "No assets to draw"}>
          <circle cx={size / 2} cy={size / 2} r={r} className="so-ring-track" strokeWidth={thick} fill="none" />
          {drawn.map((a, i) => (
            <circle key={a.key} data-segment={a.key} cx={size / 2} cy={size / 2} r={r} fill="none" stroke={segs[i].color} strokeWidth={thick}
                    strokeDasharray={`${a.len} ${circ - a.len}`} strokeDashoffset={-a.start} transform={`rotate(-90 ${size / 2} ${size / 2})`}>
              <title>{`${segs[i].label}: ${segs[i].value.toLocaleString()} (${fmtShare((100 * segs[i].value) / total!)})`}</title>
            </circle>
          ))}
          <text x="50%" y="48%" textAnchor="middle" className="so-ring-value">{total === null ? "—" : total.toLocaleString()}</text>
          <text x="50%" y="62%" textAnchor="middle" className="so-ring-caption">Total Assets</text>
        </svg>
        <ul className="so-legend" aria-label="Distribution legend">
          {segs.map((s) => (
            <li key={s.key} data-segment={s.key}>
              <span className="so-swatch" style={{ background: s.color }} />
              <span className="so-legend-name">{s.label}</span>
              <span className="so-legend-count">{s.value.toLocaleString()}</span>
              <span className="so-legend-share">{fmtShare((100 * s.value) / total!)}</span>
            </li>
          ))}
        </ul>
      </div>
      {total === null ? null : (
        <p className="so-note">
          Shares are taken over all {total.toLocaleString()} assets, which these segments split exactly.
          {unmeasured.length > 0 && <> Not drawn, because Core does not measure them: {unmeasured.map((c) => c.label).join(", ")}.</>}
        </p>
      )}
    </div>
  );
}

function RecentAssets({ range, now, can, q }: { range: Range; now: number; can: boolean; q: ReturnType<typeof useInventory> }) {
  const all = q.assets.data?.assets;
  const rows = all ? newestBy(all.filter((a) => inRange(a.first_seen, range.days, now)), (a) => a.first_seen) : [];
  // Environment is an operator-set tag; with none set anywhere the column
  // would be a column of blanks, so it is left out.
  const showEnv = !!all?.some((a) => a.environment);
  return (
    <div className="card so-panel" aria-label="Recently Discovered Assets">
      <div className="so-panel-head">
        <h2>Recently Discovered Assets</h2>
        <Link className="so-viewall" to={`/dashboard/recent-assets?range=${range.key}`}>View All →</Link>
      </div>
      {!can ? <p className="muted">This account cannot read assets.</p>
        : q.assets.isLoading ? <p className="muted">Loading…</p>
        : q.assets.error ? <p className="error">Could not load assets.</p>
        : <AssetTable rows={rows.slice(0, RECENT_ROWS)} showEnv={showEnv} ports={q.ports.data?.ports} empty={`No assets were first seen in the ${range.label.toLowerCase()}.`} />}
    </div>
  );
}

function RecentFindings({ range, now, can, q }: { range: Range; now: number; can: boolean; q: ReturnType<typeof useAllFindings> }) {
  const rows = q.data ? newestBy(q.data.filter((f) => inRange(f.first_seen, range.days, now)), (f) => f.first_seen) : [];
  return (
    <div className="card so-panel" aria-label="Recent Security Findings">
      <div className="so-panel-head">
        <h2>Recent Security Findings</h2>
        <Link className="so-viewall" to={`/dashboard/recent-findings?range=${range.key}`}>View All →</Link>
      </div>
      {!can ? <p className="muted">This account cannot read findings.</p>
        : q.isLoading ? <p className="muted">Loading…</p>
        : q.error ? <p className="error">Could not load findings.</p>
        : <FindingTable rows={rows.slice(0, RECENT_ROWS)} empty={`No findings were first seen in the ${range.label.toLowerCase()}.`} />}
    </div>
  );
}
