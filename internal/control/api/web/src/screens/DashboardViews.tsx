import { useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { useQueries, useQuery } from "@tanstack/react-query";
import { api, has, type AssetSummary, type FindingSummary } from "../lib/api";
import { useAuth } from "../lib/auth";
import { PageHead } from "../components/PageHead";
import { IconTile } from "../components/CategoryIcon";
import { Pager, PAGE_ROWS } from "../components/Discovery";
import { shortDate } from "../lib/discovery";
import {
  allAssets, allFindings, assetKind, categoryByKey, inRange, matchFinding, newestBy, rangeFor, SEVERITY_COLOR, SEVERITY_LABEL,
} from "../lib/dashboard";

// The Security Overview's data and its drill-down views: the full listings
// behind each "View All →", the search results, and the honest page a card
// opens when Core holds no data for its category.

const STALE = 30_000;

// The whole asset inventory, read to the last page (a count is exact only
// over every page), and the open-port read that names database hosts.
export function useInventory(enabled: boolean) {
  const assets = useQuery({ queryKey: ["dashboard", "assets-all"], queryFn: () => allAssets((q) => api.listAssets(q)), enabled, staleTime: STALE });
  const ports = useQuery({ queryKey: ["open-ports"], queryFn: () => api.openPorts(), enabled, staleTime: STALE });
  return { assets, ports };
}

// Every finding, any status: the list has no date filter, so the period is
// applied to the complete set rather than to one priority-ordered page.
export function useAllFindings(enabled: boolean) {
  return useQuery({ queryKey: ["dashboard", "findings-all"], queryFn: () => allFindings((q) => api.listFindings(q)), enabled, staleTime: STALE });
}

export function AssetTable({ rows, showEnv, ports, empty }: { rows: AssetSummary[]; showEnv: boolean; ports?: { asset_id: string; service?: string | null }[]; empty: string }) {
  const cols = showEnv ? 6 : 5;
  return (
    <div className="table-wrap so-table">
      <table>
        <thead>
          <tr><th>Name</th><th>Type</th><th>IP / Endpoint</th>{showEnv && <th>Environment</th>}<th>First Seen</th><th>Status</th></tr>
        </thead>
        <tbody>
          {rows.length === 0 && <tr className="empty"><td colSpan={cols}>{empty}</td></tr>}
          {rows.map((a) => {
            const kind = assetKind(a, ports);
            return (
              <tr key={a.id}>
                <td>
                  {/* The hostname when Core has one; otherwise the address, then the id — never an invented name. */}
                  <Link className="so-name" to={`/assets/${a.id}`} title={a.id}>
                    <IconTile name={kind.icon} color={kind.color} dark={kind.dark} size={22} label={kind.label} />
                    <span className={a.hostname ? "" : "data"}>{a.hostname || a.address || a.id.slice(0, 8)}</span>
                  </Link>
                </td>
                <td className={kind.known ? "" : "muted"} data-kind={kind.label}>{kind.label}</td>
                <td className="data">{a.address || "—"}</td>
                {showEnv && <td>{a.environment || "—"}</td>}
                <td className="data">{shortDate(a.first_seen)}</td>
                <td title="Core records no active or inactive state for an asset.">—</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

// Module is the finding's source (network, credentialed, …), which only the
// finding's own record carries, so it is read per shown row.
export function FindingTable({ rows, empty }: { rows: FindingSummary[]; empty: string }) {
  const details = useQueries({
    queries: rows.map((f) => ({ queryKey: ["finding", f.id], queryFn: () => api.getFinding(f.id), staleTime: 60_000 })),
  });
  return (
    <div className="table-wrap so-table">
      <table>
        <thead><tr><th>Title</th><th>Module</th><th>Severity</th><th>Asset</th><th>Time</th></tr></thead>
        <tbody>
          {rows.length === 0 && <tr className="empty"><td colSpan={5}>{empty}</td></tr>}
          {rows.map((f, i) => {
            const d = details[i];
            return (
              <tr key={f.id}>
                <td><Link to={`/findings/${f.id}`} className="data">{f.rule || "—"}</Link></td>
                <td>{d?.data?.source || (d?.isLoading ? "…" : "—")}</td>
                <td>
                  <span className="so-sev" data-severity={f.severity}>
                    <span className="so-sev-dot" style={{ background: SEVERITY_COLOR[f.severity] ?? "#94A3B8" }} />
                    {SEVERITY_LABEL[f.severity] ?? (f.severity || "—")}
                  </span>
                </td>
                <td>{f.asset_id ? <Link to={`/assets/${f.asset_id}`} className="data">{f.asset_hostname || f.asset_id.slice(0, 8)}</Link> : "—"}</td>
                <td className="data">{shortDate(f.first_seen)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function Back({ range }: { range?: string }) {
  return <Link className="so-back" to={range ? `/?range=${range}` : "/"}>← Security Overview</Link>;
}

// View All for Recently Discovered Assets: every asset first seen in the
// period, newest first, paged.
export function RecentAssetsList() {
  const { session } = useAuth();
  const can = has(session, "asset.read");
  const [params] = useSearchParams();
  const range = rangeFor(params.get("range"));
  const inv = useInventory(can);
  const [page, setPage] = useState(0);
  const now = Date.now();
  const all = inv.assets.data?.assets;
  const rows = all ? newestBy(all.filter((a) => inRange(a.first_seen, range.days, now)), (a) => a.first_seen) : [];
  return (
    <section className="so">
      <Back range={range.key} />
      <PageHead title="Recently Discovered Assets" sub={`Assets first seen in the ${range.label.toLowerCase()}, newest first.`} />
      <div className="card so-panel">
        <div className="so-panel-head"><h2>{range.label}</h2><Pager page={page} total={rows.length} onPage={setPage} /></div>
        {!can ? <p className="muted">This account cannot read assets.</p>
          : inv.assets.isLoading ? <p className="muted">Loading…</p>
          : inv.assets.error ? <p className="error">Could not load assets.</p>
          : <AssetTable rows={rows.slice(page * PAGE_ROWS, (page + 1) * PAGE_ROWS)} showEnv={!!all?.some((a) => a.environment)}
                        ports={inv.ports.data?.ports} empty={`No assets were first seen in the ${range.label.toLowerCase()}.`} />}
      </div>
    </section>
  );
}

// View All for Recent Security Findings: every finding first seen in the
// period, any status, newest first, paged.
export function RecentFindingsList() {
  const { session } = useAuth();
  const can = has(session, "finding.read");
  const [params] = useSearchParams();
  const range = rangeFor(params.get("range"));
  const findings = useAllFindings(can);
  const [page, setPage] = useState(0);
  const now = Date.now();
  const rows = findings.data ? newestBy(findings.data.filter((f) => inRange(f.first_seen, range.days, now)), (f) => f.first_seen) : [];
  return (
    <section className="so">
      <Back range={range.key} />
      <PageHead title="Recent Security Findings" sub={`Findings first seen in the ${range.label.toLowerCase()}, any status, newest first.`} />
      <div className="card so-panel">
        <div className="so-panel-head"><h2>{range.label}</h2><Pager page={page} total={rows.length} onPage={setPage} /></div>
        {!can ? <p className="muted">This account cannot read findings.</p>
          : findings.isLoading ? <p className="muted">Loading…</p>
          : findings.error ? <p className="error">Could not load findings.</p>
          : <FindingTable rows={rows.slice(page * PAGE_ROWS, (page + 1) * PAGE_ROWS)} empty={`No findings were first seen in the ${range.label.toLowerCase()}.`} />}
      </div>
    </section>
  );
}

// The dashboard search. Assets are matched by Core (hostname or a current
// address); findings and vulnerabilities by rule, CVE, category or asset over
// the complete finding set, which has no server-side text filter.
export function DashboardSearch() {
  const { session } = useAuth();
  const canAssets = has(session, "asset.read");
  const canFindings = has(session, "finding.read");
  const [params] = useSearchParams();
  const q = (params.get("q") ?? "").trim();
  const assets = useQuery({
    queryKey: ["dashboard", "asset-search", q],
    queryFn: () => allAssets((qs) => api.listAssets(`${qs}&${new URLSearchParams({ q })}`)),
    enabled: canAssets && !!q,
  });
  const findings = useAllFindings(canFindings && !!q);
  const [aPage, setAPage] = useState(0);
  const [fPage, setFPage] = useState(0);
  const aRows = assets.data?.assets ?? [];
  const fRows = findings.data ? newestBy(findings.data.filter((f) => matchFinding(f, q)), (f) => f.first_seen) : [];
  return (
    <section className="so">
      <Back />
      <PageHead title="Search" sub={q ? `Results for “${q}”.` : "Enter a search on the Security Overview."} />
      {q && (
        <div className="so-row">
          <div className="card so-panel">
            <div className="so-panel-head"><h2>Assets</h2><Pager page={aPage} total={aRows.length} onPage={setAPage} /></div>
            {!canAssets ? <p className="muted">This account cannot read assets.</p>
              : assets.isLoading ? <p className="muted">Loading…</p>
              : assets.error ? <p className="error">Could not search assets.</p>
              : <AssetTable rows={aRows.slice(aPage * PAGE_ROWS, (aPage + 1) * PAGE_ROWS)} showEnv={aRows.some((a) => a.environment)}
                            empty="No asset's hostname or current address matches." />}
          </div>
          <div className="card so-panel">
            <div className="so-panel-head"><h2>Findings &amp; vulnerabilities</h2><Pager page={fPage} total={fRows.length} onPage={setFPage} /></div>
            {!canFindings ? <p className="muted">This account cannot read findings.</p>
              : findings.isLoading ? <p className="muted">Loading…</p>
              : findings.error ? <p className="error">Could not search findings.</p>
              : <FindingTable rows={fRows.slice(fPage * PAGE_ROWS, (fPage + 1) * PAGE_ROWS)} empty="No finding's rule, CVE, category or asset matches." />}
          </div>
        </div>
      )}
    </section>
  );
}

// A card for a category Core holds no data for opens this: what the category
// would need, and no figures.
export function CategoryView() {
  const { key } = useParams();
  const c = categoryByKey(key);
  if (!c) return <section className="so"><Back /><PageHead title="Unknown category" /></section>;
  return (
    <section className="so">
      <Back />
      <PageHead title={c.label} sub="Not yet integrated" />
      <div className="card so-panel so-gap">
        <IconTile name={c.icon} color={c.color} dark={c.dark} />
        <div>
          <p><b>Not yet integrated.</b> {c.gap}</p>
          <p className="muted small">The Security Overview shows — for this category until Core collects it. No figure is estimated.</p>
        </div>
      </div>
    </section>
  );
}
