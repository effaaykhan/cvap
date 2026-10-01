import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useQueries, useQuery } from "@tanstack/react-query";
import { api, has, type Asset } from "../lib/api";
import { useAuth } from "../lib/auth";
import { PageHead } from "../components/PageHead";
import { Columns, Donut } from "../components/Charts";
import { AssetRef, Gap, Metric, Pager, PAGE_ROWS, Panel, PortStateDonut, QueryState, TableWrap } from "../components/Discovery";
import { ago, exactRead } from "../lib/console";
import {
  countBy, fetchAllAssets, perDay, plural, portState, recency, RECENCY, RECENCY_ORDER, serviceState, shortDate, shortDay,
} from "../lib/discovery";

// Asset Inventory: what exists and what Core knows about each thing. The
// question is "what is there", not "what is vulnerable" — that is Triage, and
// findings appear here only as one quiet column. Every figure is a read Core
// serves; the per-row OS, service and identity columns come from each visible
// asset's own detail read, 25 at a time, because the list read does not carry
// them.
export function AssetInventory() {
  const { session } = useAuth();
  const canAssets = has(session, "asset.read");
  const all = useQuery({ queryKey: ["discover-assets"], queryFn: () => fetchAllAssets(api.listAssets), enabled: canAssets });
  const ports = useQuery({ queryKey: ["open-ports"], queryFn: () => api.openPorts(), enabled: canAssets });

  const [q, setQ] = useState("");
  const [sort, setSort] = useState<"last_seen" | "first_seen">("last_seen");
  const [page, setPage] = useState(0);

  const assets = all.data?.assets ?? [];
  const presence = all.data?.presence;
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return assets
      .filter((a) => !needle || a.id.toLowerCase().includes(needle) || (a.address ?? "").toLowerCase().includes(needle) || (a.hostname ?? "").toLowerCase().includes(needle))
      .sort((a, b) => (b[sort] ?? "").localeCompare(a[sort] ?? "") || a.id.localeCompare(b.id));
  }, [assets, q, sort]);
  const visible = rows.slice(page * PAGE_ROWS, (page + 1) * PAGE_ROWS);
  const details = useQueries({
    queries: visible.map((a) => ({ queryKey: ["asset", a.id], queryFn: () => api.getAsset(a.id), staleTime: 60_000 })),
  });

  const firstSeen = perDay(assets.map((a) => a.first_seen));
  const seen = countBy(assets, (a) => recency(a.last_seen));
  const recent = (seen.day ?? 0) + (seen.week ?? 0);
  const latest = assets.reduce<string | undefined>((m, a) => (!m || a.last_seen > m ? a.last_seen : m), undefined);
  const withAddress = assets.filter((a) => a.address).length;
  const portRows = ports.data?.ports ?? [];
  const recognised = portRows.filter((p) => portState(p) === "recognised").length;
  const portAssets = new Set(portRows.map((p) => p.asset_id)).size;
  const count = all.data ? `${assets.length}${all.data.complete ? "" : "+"}` : "—";

  return (
    <section className="discover">
      <PageHead
        title="Asset Inventory"
        sub="Every asset Core has correlated from scan observations, and what is known about each: when it was first and last seen, its addresses, its open ports and how they were identified, and any operating system attributed to it."
        meta={<>{all.data ? `${plural(assets.length, "asset")} · ${all.data.complete ? "complete" : "first " + assets.length}` : ""}</>}
      />
      {!canAssets && <Gap>This page reads assets, which this session's permissions do not include.</Gap>}

      <div className="metric-strip">
        <Metric label="Assets" value={count} qual="inventoried"
                foot={firstSeen.length ? `first seen ${shortDay(firstSeen[0].day)}${firstSeen.length > 1 ? ` – ${shortDay(firstSeen[firstSeen.length - 1].day)}` : ""}` : "correlated from observations"} />
        <Metric label="Live addresses" value={presence ? presence.total : "—"} qual={all.data ? `${withAddress} of ${assets.length} assets hold one` : undefined}
                tone={presence && presence.total === 0 && assets.length > 0 ? "warn" : undefined}
                foot={presence ? (presence.total === 0 ? "no asset currently holds a live address" : `${presence.present} present · ${presence.unknown} unknown · ${presence.responder} responder`) : "current address windows"} />
        <Metric label="Seen in the last 7 days" value={all.data ? recent : "—"} qual={all.data ? `of ${assets.length}` : undefined}
                tone={all.data && assets.length > 0 && recent === 0 ? "warn" : undefined}
                foot={latest ? `latest sighting ${ago(latest)}` : "no sightings yet"} />
        <Metric label="Open ports" value={ports.data ? `${portRows.length}${ports.data.truncated ? "+" : ""}` : "—"}
                qual={ports.data ? `${recognised} recognised` : undefined}
                foot={ports.data ? `${plural(portAssets, "asset")}${ports.data.truncated ? ` · the ${ports.data.limit} most recently seen` : ""}` : "listening endpoints"} />
      </div>

      <div className="disc-grid-3">
        <Panel title="First seen, per day" aside="when each asset first appeared">
          <QueryState loading={all.isLoading} error={all.error} what="assets" />
          {all.data && (firstSeen.length ? <Columns data={firstSeen.map((d) => ({ key: d.day, label: d.day.slice(5), value: d.n }))} unit="assets" /> : <p className="empty">No assets yet. A discovery scan creates them.</p>)}
        </Panel>
        <Panel title="Last seen" aside="time since each asset's latest sighting">
          <QueryState loading={all.isLoading} error={all.error} what="assets" />
          {all.data && <Donut center="assets" segments={RECENCY_ORDER.map((k) => ({ key: k, label: RECENCY[k].label, tone: RECENCY[k].tone, value: seen[k] ?? 0 }))} />}
        </Panel>
        <Panel title="Open-port identification" aside={<Link to="/discover/discovery/unknown-assets">unidentified →</Link>}>
          <QueryState loading={ports.isLoading} error={ports.error} what="open ports" />
          {ports.data && <PortStateDonut states={portRows.map(portState)} caption={ports.data.truncated ? `${ports.data.limit} most recently seen` : undefined} />}
        </Panel>
      </div>

      <Panel title="Inventory" aside={<Pager page={page} total={rows.length} onPage={setPage} />}>
        <div className="disc-toolbar">
          <input placeholder="address or asset id…" value={q} onChange={(e) => { setQ(e.target.value); setPage(0); }} aria-label="Search assets" />
          <select value={sort} onChange={(e) => { setSort(e.target.value as "last_seen" | "first_seen"); setPage(0); }} aria-label="Sort assets">
            <option value="last_seen">most recently seen</option>
            <option value="first_seen">most recently discovered</option>
          </select>
          {all.data && assets.length > 0 && withAddress === 0 && (
            <span className="disc-toolbar-note">No asset holds a current address, so assets are listed by id.</span>
          )}
        </div>
        <QueryState loading={all.isLoading} error={all.error} what="assets" />
        {all.data && (
          <TableWrap>
            <table className="disc-table">
              <thead>
                <tr>
                  <th>Asset</th><th>First seen</th><th>Last seen</th><th>Operating system</th>
                  <th>Open ports</th><th className="num">Identity keys</th><th className="num hide-sm">Open findings</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((a, i) => {
                  const d = details[i]?.data;
                  return (
                    <tr key={a.id}>
                      <td><AssetRef a={a} note={withAddress > 0} />{a.fragile && <span className="chip chip-high" style={{ marginLeft: ".4rem" }} title="marked fragile: scans treat it gently">fragile</span>}</td>
                      <td className="data">{shortDate(a.first_seen)}</td>
                      <td className="data">{shortDate(a.last_seen)} <span className="faint">· {ago(a.last_seen)}</span></td>
                      <td>{d ? <OsCell a={d} /> : <Pending failed={!!details[i]?.error} />}</td>
                      <td>{d ? <PortsCell a={d} /> : <Pending failed={!!details[i]?.error} />}</td>
                      <td className="num">{d ? d.identity_keys_total || <span className="faint">0</span> : <Pending failed={!!details[i]?.error} />}</td>
                      <td className="num hide-sm">{a.open_findings ? <Link to={`/assets/${a.id}`} className="muted">{a.open_findings}</Link> : <span className="faint">0</span>}</td>
                    </tr>
                  );
                })}
                {visible.length === 0 && <tr className="empty"><td colSpan={7}>{assets.length ? "No asset matches that search." : "No assets yet. A discovery scan creates them from what answers."}</td></tr>}
              </tbody>
            </table>
          </TableWrap>
        )}
        <div className="foot-note">
          Operating system, open ports and identity keys are read from each visible asset's own record. Not collected today, so not shown:
          hostnames, MAC addresses, device type, vendor, owner, environment and criticality. Open findings are context only —
          vulnerability posture lives in <Link to="/assess/vulnerabilities">Vulnerabilities</Link>.
        </div>
      </Panel>
    </section>
  );
}

function Pending({ failed }: { failed: boolean }) {
  return failed ? <span className="faint" title="this asset's record could not be read">unavailable</span> : <span className="faint">…</span>;
}

// The OS as Core concluded it: an exact credentialed read, or an inference
// with its confidence — or, for most assets today, nothing.
function OsCell({ a }: { a: Asset }) {
  if (!a.distro_family) return <span className="unknown">not attributed</span>;
  const exact = exactRead(a.os_provenance);
  return (
    <span>
      <span className="data">{a.distro_family}{a.distro_release ? ` ${a.distro_release}` : ""}</span>{" "}
      <span className="faint small">{exact ? "exact read" : a.os_confidence != null ? `inferred · ${a.os_confidence.toFixed(2)}` : "inferred"}</span>
    </span>
  );
}

function PortsCell({ a }: { a: Asset }) {
  if (a.services.length === 0) return <span className="faint">none recorded</span>;
  const st = countBy(a.services, serviceState);
  return (
    <span className="ports-cell">
      <b className="data">{a.services.length}</b>
      {st.recognised ? <span className="chip chip-ok">{st.recognised} recognised</span> : null}
      {st.answered ? <span className="chip chip-warn">{st.answered} unidentified</span> : null}
      {st.probed ? <span className="chip chip-muted">{st.probed} no match</span> : null}
    </span>
  );
}
