import { Link, useSearchParams } from "react-router-dom";
import { has } from "../lib/api";
import { useAuth } from "../lib/auth";
import { IconTile } from "../components/CategoryIcon";
import { RangePicker } from "../components/RangePicker";
import {
  arcs, CATEGORIES, distribution, fmtCount, fmtShare, inRange, measure, newestBy, rangeFor, RANGES, share, UNCLASSIFIED,
  type Category, type Measures, type Range,
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

  // A read that failed — first or on a refresh — counts as unread: its last
  // figures are not shown as current.
  const assetsRead = inv.assets.error ? undefined : inv.assets.data;
  const ms = measure({ assets: assetsRead?.assets, addresses: assetsRead?.addresses, openPorts: inv.ports.error ? undefined : inv.ports.data });

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
        {CATEGORIES.map((c) => <CategoryCard key={c.key} c={c} ms={ms} />)}
      </div>

      <div className="so-row">
        <Distribution ms={ms} />
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

function CategoryCard({ c, ms }: { c: Category; ms: Measures }) {
  const m = ms[c.key];
  const pct = share(c.key, ms);
  const integrated = !!c.to;
  const title = !integrated && m.count === null ? `Not yet integrated. ${c.gap ?? ""}`.trim()
    : c.key === "total" ? `Every asset Core holds — the base every share is taken over. Its percentage is how much of it is classified into a kind${pct === null ? "; that cannot be measured yet, because the database count is capped" : ""}.`
    : m.note;
  return (
    <Link className={`card so-card${m.count === null ? " so-card-gap" : ""}`} to={c.to ?? `/dashboard/categories/${c.key}`} title={title}
          data-category={c.key} aria-label={`${c.label}: ${fmtCount(m)}${integrated ? "" : ", not yet integrated"}`}>
      <span className="so-card-icon"><IconTile name={c.icon} color={c.color} deep={c.deep} /></span>
      <span className="so-card-name">{c.label}</span>
      <span className="so-card-count">{fmtCount(m)}</span>
      <span className="so-card-share">{fmtShare(pct)}{c.key === "total" && pct !== null && <span className="so-share-what"> classified</span>}</span>
    </Link>
  );
}

// The distribution: a ring split by kind — each asset in at most one, so the
// segments never double-count — with the eleven categories in a two-column
// legend beside it, in card order and colour, carrying the same counts and
// shares as the cards. Total Assets sits in the centre. IP Addresses is listed
// but never drawn: it overlaps every kind. An unmeasured kind reads "—" and
// leaves its part of the ring empty; nothing is borrowed to fill it.
function Distribution({ ms }: { ms: Measures }) {
  const total = ms.total.count;
  const segs = distribution(ms);
  const size = 168, thick = 20, r = (size - thick) / 2, circ = 2 * Math.PI * r;
  const drawn = total !== null && total > 0 ? arcs(segs, total, circ) : [];
  const unmeasured = CATEGORIES.filter((c) => c.key !== "total" && c.key !== "ip" && ms[c.key].count === null);
  return (
    <div className="card so-panel so-dist" aria-label="Asset Distribution">
      <div className="so-panel-head"><h2>Asset Distribution</h2><span className="so-aside">current inventory</span></div>
      <div className="so-dist-body">
        <svg className="so-ring" viewBox={`0 0 ${size} ${size}`} width={size} height={size} role="img"
             aria-label={segs.length ? segs.map((s) => `${s.label} ${s.value}`).join(", ") : "No asset kind measured yet"}>
          <circle cx={size / 2} cy={size / 2} r={r} className="so-ring-track" strokeWidth={thick} fill="none" />
          {drawn.map((a) => {
            const seg = segs.find((x) => x.key === a.key)!;
            return (
              <circle key={a.key} data-segment={a.key} cx={size / 2} cy={size / 2} r={r} fill="none" stroke={seg.color} strokeWidth={thick}
                      strokeDasharray={`${a.len} ${circ - a.len}`} strokeDashoffset={-a.start} transform={`rotate(-90 ${size / 2} ${size / 2})`}>
                <title>{`${seg.label}: ${seg.value.toLocaleString()} (${fmtShare((100 * seg.value) / total!)})`}</title>
              </circle>
            );
          })}
          <text x="50%" y="48%" textAnchor="middle" className="so-ring-value">{total === null ? "—" : total.toLocaleString()}</text>
          <text x="50%" y="62%" textAnchor="middle" className="so-ring-caption">Total Assets</text>
        </svg>
        <ul className="so-legend" aria-label="Distribution legend">
          {CATEGORIES.map((c) => (
            <li key={c.key} data-category={c.key} className={drawn.some((a) => a.key === c.key) ? "drawn" : undefined}
                title={c.key === "ip" ? "Overlaps every kind, so it is listed, not drawn." : ms[c.key].count === null ? ms[c.key].note ?? c.gap : undefined}>
              <span className="so-swatch" style={{ background: c.color }} />
              <span className="so-legend-name">{c.label}</span>
              <span className="so-legend-count">{fmtCount(ms[c.key])}</span>
              <span className="so-legend-share">{fmtShare(share(c.key, ms))}{c.key === "total" && share(c.key, ms) !== null && <span className="so-share-what"> classified</span>}</span>
            </li>
          ))}
          {ms.unclassified.count !== null && (
            <li data-category="unclassified" className={drawn.some((a) => a.key === UNCLASSIFIED.key) ? "drawn" : undefined}
                title="Assets measured as none of the kinds above.">
              <span className="so-swatch" style={{ background: UNCLASSIFIED.color }} />
              <span className="so-legend-name">{UNCLASSIFIED.label}</span>
              <span className="so-legend-count">{ms.unclassified.count.toLocaleString()}</span>
              <span className="so-legend-share">{fmtShare(share("unclassified", ms))}</span>
            </li>
          )}
        </ul>
      </div>
      {total !== null && (
        <p className="so-note">
          Each asset counts in at most one kind, and every share is its count over the {total.toLocaleString()} assets. IP Addresses overlaps
          the kinds, so it is listed but not drawn.
          {unmeasured.length > 0 && <> Not measured yet, so not drawn: {unmeasured.map((c) => c.label).join(", ")}.</>}
          {ms.databases.count === null && ms.databases.atLeast !== undefined && <> Databases is at least {ms.databases.atLeast}: Core's open-port list is capped.</>}
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
