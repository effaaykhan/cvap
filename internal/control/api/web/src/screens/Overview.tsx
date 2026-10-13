import { useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { has } from "../lib/api";
import { useAuth } from "../lib/auth";
import { CategoryIcon } from "../components/CategoryIcon";
import {
  CATEGORIES, distribution, fmtCount, fmtShare, inRange, measure, newestBy, rangeFor, RANGES, share, UNCLASSIFIED,
  type Category, type CategoryKey, type Measure, type Range,
} from "../lib/dashboard";
import { AssetTable, FindingTable, useAllFindings, useInventory } from "./DashboardViews";

// Security Overview: the operator landing. The twelve cards, their shares and
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
  const navigate = useNavigate();
  const [q, setQ] = useState("");

  const inv = useInventory(canAssets);
  const findings = useAllFindings(canFindings);
  const now = Date.now();

  const ms = measure({ assets: inv.assets.data?.assets, addresses: inv.assets.data?.addresses, openPorts: inv.ports.data });
  const total = ms.total.count;

  const search = (e: FormEvent) => {
    e.preventDefault();
    if (q.trim()) navigate(`/dashboard/search?${new URLSearchParams({ q: q.trim() })}`);
  };
  const setRange = (key: string) => {
    const next = new URLSearchParams(params);
    next.set("range", key);
    setParams(next, { replace: true });
  };

  return (
    <section className="so">
      <div className="so-top">
        <form className="so-search" role="search" onSubmit={search}>
          <CategoryIcon name="search" size={16} />
          <input type="search" value={q} onChange={(e) => setQ(e.target.value)}
                 placeholder="Search assets, vulnerabilities, findings..." aria-label="Search assets, vulnerabilities, findings" />
        </form>
        <label className="so-range">
          <CategoryIcon name="calendar" size={16} />
          <select value={range.key} onChange={(e) => setRange(e.target.value)} aria-label="Time range">
            {RANGES.map((r) => <option key={r.key} value={r.key}>{r.label}</option>)}
          </select>
        </label>
      </div>

      <h1 className="so-title">Security Overview</h1>
      <p className="so-sub">Real-time visibility of your assets, security posture, and application security across your environment.</p>

      {!canAssets && <p className="muted small so-status">This account cannot read assets (it lacks the asset.read permission), so every count reads —.</p>}
      {canAssets && inv.assets.isLoading && <p className="muted small so-status">Loading the asset inventory…</p>}
      {canAssets && inv.assets.error && <p className="error small so-status">Could not load the asset inventory, so its counts read —.</p>}

      <div className="so-cards" aria-label="Asset categories">
        {CATEGORIES.map((c) => <CategoryCard key={c.key} c={c} m={ms[c.key]} total={total} />)}
      </div>

      <div className="so-row">
        <Distribution ms={ms} total={total} />
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
  const title = !integrated ? `Not yet integrated. ${c.gap ?? ""}`.trim() : m.count === null && m.note ? m.note : undefined;
  return (
    <Link className={`card so-card${integrated ? "" : " so-card-gap"}`} to={c.to ?? `/dashboard/categories/${c.key}`} title={title}
          data-category={c.key} aria-label={`${c.label}: ${fmtCount(m)}${integrated ? "" : ", not yet integrated"}`}>
      <span className="so-card-icon" style={{ color: c.color, background: `${c.color}1f` }}><CategoryIcon name={c.icon} color={c.color} /></span>
      <span className="so-card-name">{c.label}</span>
      <span className="so-card-count">{fmtCount(m)}</span>
      <span className="so-card-share">{fmtShare(pct)}</span>
    </Link>
  );
}

// The distribution: a ring whose arcs are each slice's share of the WHOLE
// inventory, so an unmeasured category leaves its part of the ring empty
// rather than being absorbed by the others. The legend repeats the card
// values exactly.
function Distribution({ ms, total }: { ms: Record<CategoryKey, Measure>; total: number | null }) {
  const segs = distribution(ms, total);
  const size = 168, thick = 20, r = (size - thick) / 2, circ = 2 * Math.PI * r;
  let offset = 0;
  const unclassified = segs.find((s) => s.key === "unclassified");
  return (
    <div className="card so-panel so-dist" aria-label="Asset Distribution">
      <div className="so-panel-head"><h2>Asset Distribution</h2><span className="so-aside">current inventory</span></div>
      <div className="so-dist-body">
        <svg className="so-ring" viewBox={`0 0 ${size} ${size}`} width={size} height={size} role="img"
             aria-label={segs.length ? segs.map((s) => `${s.label} ${s.value}`).join(", ") : "No classified assets to draw"}>
          <circle cx={size / 2} cy={size / 2} r={r} className="so-ring-track" strokeWidth={thick} fill="none" />
          {total !== null && total > 0 && segs.map((s) => {
            const len = (s.value / total) * circ;
            const el = (
              <circle key={s.key} data-segment={s.key} cx={size / 2} cy={size / 2} r={r} fill="none" stroke={s.color} strokeWidth={thick}
                      strokeDasharray={`${len} ${circ - len}`} strokeDashoffset={-offset} transform={`rotate(-90 ${size / 2} ${size / 2})`}>
                <title>{`${s.label}: ${s.value.toLocaleString()} (${fmtShare((100 * s.value) / total)})`}</title>
              </circle>
            );
            offset += len;
            return el;
          })}
          <text x="50%" y="48%" textAnchor="middle" className="so-ring-value">{total === null ? "—" : total.toLocaleString()}</text>
          <text x="50%" y="62%" textAnchor="middle" className="so-ring-caption">Total Assets</text>
        </svg>
        <ul className="so-legend" aria-label="Distribution legend">
          {CATEGORIES.map((c) => (
            <li key={c.key} data-category={c.key} title={c.to ? undefined : "Not yet integrated"}>
              <span className="so-swatch" style={{ background: c.color }} />
              <span className="so-legend-name">{c.label}</span>
              <span className="so-legend-count">{fmtCount(ms[c.key])}</span>
              <span className="so-legend-share">{fmtShare(share(c, ms[c.key], total))}</span>
            </li>
          ))}
          {unclassified && total !== null && (
            <li data-category="unclassified">
              <span className="so-swatch" style={{ background: UNCLASSIFIED.color }} />
              <span className="so-legend-name">{UNCLASSIFIED.label}</span>
              <span className="so-legend-count">{unclassified.value.toLocaleString()}</span>
              <span className="so-legend-share">{fmtShare((100 * unclassified.value) / total)}</span>
            </li>
          )}
        </ul>
      </div>
      {total !== null && segs.length === 0 && (
        <p className="so-note">
          The ring has no segments: Core does not classify assets by kind yet, so no share of the {total.toLocaleString()} assets can be
          drawn. Shares are each category's count over the whole inventory.
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
