import { useState } from "react";
import { Link } from "react-router-dom";
import { useQueries, useQuery } from "@tanstack/react-query";
import { api, has, type Scan, type ScanResults } from "../lib/api";
import { useAuth } from "../lib/auth";
import { PageHead } from "../components/PageHead";
import { HBars, SegmentBar } from "../components/Charts";
import { Gap, Metric, Pager, PAGE_ROWS, Panel, QueryState, TableWrap } from "../components/Discovery";
import { ago, worstFirst } from "../lib/console";
import { countBy, duration, fmtSpan, plural, shortDate, shortDay, topN } from "../lib/discovery";

// Network Discovery: what the discovery engine was asked to do and what it
// saw. Scans and their status come from the scan list; hosts and ports come
// from each scan's own results, which are read from observations and so thin
// out as observations are pruned. The engine's method is stated, not implied:
// a TCP connect per scanned port, open ports recorded, no name resolution.
const RESULT_SCANS = 8; // most recent discovery scans whose results are read

const STATUS = [
  { key: "completed", label: "completed", tone: "ok", match: ["completed"] },
  { key: "running", label: "running", tone: "accent", match: ["running", "planning"] },
  { key: "pending", label: "pending", tone: "medium", match: ["pending"] },
  { key: "failed", label: "failed / killed", tone: "danger", match: ["failed", "killed"] },
  { key: "cancelled", label: "cancelled", tone: "muted", match: ["cancelled"] },
];
const DOT: Record<string, string> = { completed: "ok", running: "accent", planning: "accent", pending: "medium", failed: "danger", killed: "danger", cancelled: "muted" };

export function NetworkDiscovery() {
  const { session } = useAuth();
  const canScans = has(session, "scan.read");
  const canZones = has(session, "zone.read");
  const canPoints = has(session, "scan_point.read");

  const scans = useQuery({ queryKey: ["scans", "?limit=200"], queryFn: () => api.listScans("?limit=200"), enabled: canScans });
  const zones = useQuery({ queryKey: ["zones"], queryFn: () => api.listZones(), enabled: canZones });
  const points = useQuery({ queryKey: ["scan-points"], queryFn: () => api.listScanPoints(), enabled: canPoints });

  const disc = (scans.data?.scans ?? []).filter((s) => s.scan_type === "discovery");
  const withResults = disc.slice(0, RESULT_SCANS);
  const resultQs = useQueries({
    queries: withResults.map((s) => ({ queryKey: ["scan-results", s.id], queryFn: () => api.scanResults(s.id), staleTime: 60_000 })),
  });
  const results = new Map<string, ScanResults>();
  withResults.forEach((s, i) => { const r = resultQs[i]?.data; if (r) results.set(s.id, r); });

  const [page, setPage] = useState(0);
  const latestDone = disc.find((s) => s.status === "completed");
  const latest = latestDone ? results.get(latestDone.id) : undefined;
  const sps = points.data?.scan_points ?? [];
  const capable = sps.filter((p) => p.capabilities.includes("discovery"));
  const healthy = capable.filter((p) => p.health === "healthy").length;
  const status = STATUS.map((s) => ({ key: s.key, label: s.label, tone: s.tone, value: disc.filter((d) => s.match.includes(d.status)).length }));
  const done = disc.filter((s) => s.status === "completed" && s.started_at && s.completed_at);
  const durations = done.map((s) => new Date(s.completed_at!).getTime() - new Date(s.started_at!).getTime()).sort((a, b) => a - b);
  const median = durations.length ? durations[Math.floor(durations.length / 2)] : null;

  const portHosts = latest ? countBy(dedupe(latest.ports.map((p) => `${p.port}/${p.protocol}|${p.address}`)), (k) => k.split("|")[0]) : {};
  const topPorts = topN(portHosts, 10);
  const perScan = withResults.filter((s) => results.has(s.id));

  return (
    <section className="discover">
      <PageHead
        title="Network Discovery"
        sub="Discovery scans and what each one found. Discovery tests a host with a TCP connect to each scanned port and records the ports that accept; it resolves no names and sends no ICMP or ARP."
        meta={scans.data ? `${plural(disc.length, "discovery scan")} · of ${scans.data.scans.length} scans` : ""}
      />
      {!canScans && <Gap>This page reads scans, which this session's permissions do not include.</Gap>}

      <div className="metric-strip">
        <Metric label="Discovery scans" value={scans.data ? disc.length : "—"} qual={scans.data ? `${status[0].value} completed` : undefined}
                foot={disc[0] ? `latest created ${ago(disc[0].created_at)}` : "none run yet"} />
        <Metric label="Hosts with open ports" value={latest ? latest.hosts : "—"} qual={latest ? "latest completed scan" : undefined}
                foot={latestDone ? <>scan <Link to={`/scans/${latestDone.id}`} className="data">{latestDone.id.slice(0, 8)}</Link> · {shortDate(latestDone.completed_at)}</> : "no completed discovery scan"} />
        <Metric label="Open ports found" value={latest ? `${latest.ports.length}${latest.truncated ? "+" : ""}` : "—"} qual={latest ? "latest completed scan" : undefined}
                foot={latest?.truncated ? `first ${latest.limit} returned` : "TCP ports that accepted a connect"} />
        <Metric label="Discovery scan points" value={points.data ? healthy : "—"} qual={points.data ? `of ${capable.length} healthy` : undefined}
                tone={points.data && capable.length > 0 && healthy === 0 ? "danger" : undefined}
                foot={points.data ? `${plural(sps.length, "scan point")} enrolled` : canPoints ? "loading" : "needs scan_point.read"} />
      </div>

      <div className="disc-grid-3">
        <Panel title="Discovery scan status" aside={<Link to="/scans">all scans →</Link>}>
          <QueryState loading={scans.isLoading} error={scans.error} what="scans" />
          {scans.data && (disc.length ? (
            <>
              <SegmentBar segments={status} height={10} />
              <div className="change-tiles disc-tiles">
                <div className="change-tile"><div className="n">{done.length}</div><div className="k">timed runs</div></div>
                <div className="change-tile"><div className="n">{median == null ? "—" : fmtSpan(median)}</div><div className="k">median run</div></div>
                <div className="change-tile"><div className="n">{durations.length ? fmtSpan(durations[durations.length - 1]) : "—"}</div><div className="k">longest run</div></div>
                <div className="change-tile"><div className="n">{shortDay(disc[0].created_at)}</div><div className="k">latest</div></div>
              </div>
            </>
          ) : <p className="empty">No discovery scan has run.</p>)}
        </Panel>
        <Panel title="Open ports per scan" aside={`${plural(perScan.length, "recent scan")}`}>
          {perScan.length ? (
            <HBars unit="open ports" rows={perScan.map((s) => {
              const r = results.get(s.id)!;
              return {
                key: s.id, to: `/scans/${s.id}`, label: s.id.slice(0, 8), sub: shortDay(s.created_at),
                segments: [{ key: "ports", label: "open ports", value: r.ports.length, tone: "accent" }],
              };
            })} />
          ) : <p className="empty">{resultQs.some((q) => q.isLoading) ? "Loading…" : "No discovery scan has results to show."}</p>}
        </Panel>
        <Panel title="Most common open ports" aside="hosts, latest completed scan">
          {topPorts.length ? (
            <HBars unit="hosts" rows={topPorts.map(([port, n]) => ({ key: port, label: port, segments: [{ key: "hosts", label: "hosts", value: n, tone: "accent" }] }))} />
          ) : <p className="empty">{latestDone ? (latest ? "The latest completed scan found no open ports, or its results have been pruned." : "Loading…") : "No completed discovery scan yet."}</p>}
        </Panel>
      </div>

      <div className="disc-main">
        <Panel title="Discovery scans" aside={<Pager page={page} total={disc.length} onPage={setPage} />}>
          <QueryState loading={scans.isLoading} error={scans.error} what="scans" />
          {scans.data && (
            <TableWrap>
              <table className="disc-table">
                <thead>
                  <tr><th>Scan</th><th>Status</th><th className="hide-sm">Mode</th><th>Started</th><th>Duration</th><th className="num">Hosts</th><th className="num">Open ports</th></tr>
                </thead>
                <tbody>
                  {disc.slice(page * PAGE_ROWS, (page + 1) * PAGE_ROWS).map((s) => <ScanRow key={s.id} s={s} r={results.get(s.id)} read={withResults.includes(s)} />)}
                  {disc.length === 0 && <tr className="empty"><td colSpan={7}>No discovery scan has run. Start one from <Link to="/scans">Scans</Link>.</td></tr>}
                </tbody>
              </table>
            </TableWrap>
          )}
          <div className="foot-note">
            Hosts and open ports are read from each scan's observations for the {RESULT_SCANS} most recent discovery scans; observations are
            pruned, so an older scan shows fewer and eventually none. A host is counted when at least one scanned port accepted a connect —
            a host that answered on no scanned port is not in these numbers. Click a scan for its full results.
          </div>
        </Panel>

        <div className="stack">
          <Panel title="Scan points" aside={<Link to="/health">health →</Link>}>
            {!canPoints ? <Gap>Needs scan_point.read.</Gap> : <QueryState loading={points.isLoading} error={points.error} what="scan points" />}
            {points.data && (sps.length ? worstFirst(sps).map((p) => (
              <div className="hrow" key={p.id}>
                <span>
                  <span className={`dot dot-${p.health === "healthy" ? "ok" : p.health === "offline" ? "danger" : p.health === "degraded" ? "warn" : "muted"}`} />
                  <span className="name">{p.hostname}</span>
                  {p.capabilities.includes("discovery") && <span className="chip chip-accent" style={{ marginLeft: ".4rem" }}>discovery</span>}
                  <span className="reason">{p.health_reason || `heartbeat ${ago(p.last_heartbeat)}`}</span>
                </span>
                <span className="state">{p.health}</span>
              </div>
            )) : <p className="empty">No scan point is enrolled.</p>)}
          </Panel>
          <Panel title="Zones" aside="where scan points look from">
            {!canZones ? <Gap>Needs zone.read.</Gap> : <QueryState loading={zones.isLoading} error={zones.error} what="zones" />}
            {zones.data && (zones.data.zones.length ? zones.data.zones.map((z) => (
              <div className="hrow" key={z.id}>
                <span>
                  <span className="name">{z.name}</span>
                  <span className="zone">{z.type}</span>
                  {z.description && <span className="reason">{z.description}</span>}
                </span>
                <span className="state">{plural(sps.filter((p) => p.zone_id === z.id).length, "scan point")}</span>
              </div>
            )) : <p className="empty">No zone is defined.</p>)}
          </Panel>
          <Panel title="What discovery records">
            <ul className="cap-list">
              <li><span className="chip chip-ok">recorded</span> open TCP ports, per address, per scan</li>
              <li><span className="chip chip-ok">recorded</span> the vantage zone of every observation</li>
              <li><span className="chip chip-muted">not used</span> ICMP, ARP and SYN probing</li>
              <li><span className="chip chip-muted">not recorded</span> closed or filtered ports</li>
              <li><span className="chip chip-muted">not done</span> name resolution and subnet mapping</li>
            </ul>
          </Panel>
        </div>
      </div>
    </section>
  );
}

function ScanRow({ s, r, read }: { s: Scan; r?: ScanResults; read: boolean }) {
  const running = !s.completed_at && ["running", "planning"].includes(s.status);
  return (
    <tr>
      <td><Link to={`/scans/${s.id}`} className="data">{s.id.slice(0, 8)}</Link></td>
      <td><span className={`dot dot-${DOT[s.status] ?? "muted"}`} /> {s.status}</td>
      <td className="muted hide-sm">{s.safety_mode}</td>
      <td className="data">{shortDate(s.started_at ?? s.created_at)}</td>
      <td className="data">{s.started_at ? <>{duration(s.started_at, s.completed_at)}{running && <span className="faint"> so far</span>}</> : "—"}</td>
      <td className="num">{r ? r.hosts : <span className="faint">{read ? "…" : "—"}</span>}</td>
      <td className="num">{r ? `${r.ports.length}${r.truncated ? "+" : ""}` : <span className="faint">{read ? "…" : "—"}</span>}</td>
    </tr>
  );
}

function dedupe(keys: string[]): string[] {
  return [...new Set(keys)];
}
