import { useState } from "react";
import { useQueries, useQuery } from "@tanstack/react-query";
import { api, has, type OpenPort } from "../lib/api";
import { useAuth } from "../lib/auth";
import { PageHead } from "../components/PageHead";
import { Donut, HBars } from "../components/Charts";
import { AssetRef, Gap, Metric, Pager, PAGE_ROWS, Panel, PortStateChip, PortStateDonut, QueryState, TableWrap } from "../components/Discovery";
import { ago } from "../lib/console";
import { countBy, DB_ENGINES, dbEngineForPort, isDatabaseService, plural, portState, PORT_STATE_ORDER, PORT_STATES } from "../lib/discovery";

// Databases: listening database services Core has identified, by the engines
// its rules can name — MySQL/MariaDB, PostgreSQL and Microsoft SQL Server, and
// no others. Version and how it was identified come from the asset's own
// record, read only for assets that carry a database service. Open ports on
// those engines' probe ports that nothing identified are listed apart, as
// ports, never as databases.
const DETAIL_CAP = 25;
const ENGINE_TONES = ["accent", "low", "info"];

export function Databases() {
  const { session } = useAuth();
  const canAssets = has(session, "asset.read");
  const ports = useQuery({ queryKey: ["open-ports"], queryFn: () => api.openPorts(), enabled: canAssets });
  const [page, setPage] = useState(0);

  const all = ports.data?.ports ?? [];
  const dbs = all.filter((p) => isDatabaseService(p.service));
  const onDbPorts = all.filter((p) => dbEngineForPort(p.port) && !isDatabaseService(p.service));
  const dbAssets = [...new Set(dbs.map((p) => p.asset_id))];
  const details = useQueries({
    queries: dbAssets.slice(0, DETAIL_CAP).map((id) => ({ queryKey: ["asset", id], queryFn: () => api.getAsset(id), staleTime: 60_000 })),
  });
  const svc = (p: OpenPort) => details.find((d) => d.data?.id === p.asset_id)?.data?.services.find((s) => s.port === p.port && s.protocol === p.protocol);

  const engines = Object.keys(DB_ENGINES);
  const byEngine = countBy(dbs, (p) => p.service!);
  const dbPortList = engines.flatMap((e) => DB_ENGINES[e].ports.map((port) => ({ port, engine: e })));
  const dbPortRows = dbPortList
    .map(({ port, engine }) => ({ port, engine, rows: all.filter((p) => p.port === port) }))
    .filter((r) => r.rows.length > 0);
  const partial = ports.data?.truncated ? ` among the ${ports.data.limit} most recently seen open ports` : "";

  return (
    <section className="discover">
      <PageHead
        title="Databases"
        sub="Database services Core has identified on open ports. Core can name three engines — MySQL/MariaDB from its handshake banner, PostgreSQL and Microsoft SQL Server by probe — and reports no other engine as a database."
        meta={ports.data ? `${plural(dbs.length, "database service")}${ports.data.truncated ? " · partial" : ""}` : ""}
      />
      {!canAssets && <Gap>This page reads open ports, which this session's permissions do not include.</Gap>}

      <div className="metric-strip">
        <Metric label="Database services" value={ports.data ? dbs.length : "—"} tone={dbs.length ? "ok" : undefined} qual="identified"
                foot={ports.data ? (dbs.length ? `on ${plural(dbAssets.length, "asset")}` : `none${partial}`) : "recognised by banner or probe"} />
        <Metric label="Engines seen" value={ports.data ? Object.keys(byEngine).length : "—"} qual={`of ${engines.length} Core can name`}
                foot={Object.keys(byEngine).map((k) => DB_ENGINES[k].label).join(" · ") || "MySQL/MariaDB · PostgreSQL · SQL Server"} />
        <Metric label="Unconfirmed on database ports" value={ports.data ? onDbPorts.length : "—"} tone={onDbPorts.length ? "warn" : undefined}
                qual={ports.data ? plural(new Set(onDbPorts.map((p) => p.asset_id)).size, "asset") : undefined}
                foot="open on an engine's port, not identified as it" />
        <Metric label="Versions known" value={ports.data ? dbs.filter((p) => svc(p)?.version).length : "—"} qual={ports.data ? `of ${dbs.length}` : undefined}
                foot="exact version as reported by the service" />
      </div>

      <div className="disc-grid-3">
        {/* With an identified engine, the engine split; without one, what the
            engines' ports DID show, rather than an empty ring. */}
        <Panel title={dbs.length || !dbPortRows.length ? "Identified engines" : "Identification on database ports"}
               aside={!dbs.length && dbPortRows.length ? "no engine identified yet" : undefined}>
          <QueryState loading={ports.isLoading} error={ports.error} what="open ports" />
          {ports.data && (dbs.length
            ? <Donut center="services" segments={engines.map((e, i) => ({ key: e, label: DB_ENGINES[e].label, tone: ENGINE_TONES[i], value: byEngine[e] ?? 0 }))} />
            : dbPortRows.length
              ? <PortStateDonut states={dbPortRows.flatMap((r) => r.rows).map(portState)} />
              : <p className="empty">No database service has been identified{partial}.</p>)}
        </Panel>
        <Panel title="Database ports by state" aside="every open port on an engine's port">
          {ports.data && (dbPortRows.length ? (
            <HBars unit="open ports" rows={dbPortRows.map((r) => ({
              key: String(r.port), label: `${r.port}/tcp`, sub: DB_ENGINES[r.engine].short,
              segments: PORT_STATE_ORDER.map((st) => ({
                key: st, tone: st === "recognised" ? "ok" : PORT_STATES[st].tone,
                label: st === "recognised" ? "identified as the engine" : PORT_STATES[st].label,
                value: r.rows.filter((p) => (st === "recognised" ? isDatabaseService(p.service) : !isDatabaseService(p.service) && portState(p) === st)).length,
              })),
            }))} />
          ) : <p className="empty">No open port{partial} is on a database engine's port.</p>)}
          {dbPortRows.length > 0 && (
            <div className="segbar-legend" style={{ marginTop: ".6rem" }}>
              <span className="lane"><span className="cdot tone-ok" />identified as the engine</span>
              <span className="lane"><span className="cdot tone-warn" />{PORT_STATES.answered.label}</span>
              <span className="lane"><span className="cdot tone-muted" />{PORT_STATES.probed.label}</span>
            </div>
          )}
        </Panel>
        <Panel title="How each engine is identified">
          <TableWrap>
            <table className="disc-table disc-compact">
              <thead><tr><th>Engine</th><th>Method</th><th>Ports</th></tr></thead>
              <tbody>
                {engines.map((e) => (
                  <tr key={e}><td>{DB_ENGINES[e].label}</td><td className="muted">{DB_ENGINES[e].how}</td><td className="data">{DB_ENGINES[e].ports.join(", ")}</td></tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
          <div className="foot-note">PostgreSQL and SQL Server answer only to a probe, so a safe-mode scan sees their ports open and unidentified. The SQL Server rule identifies the protocol, not a product or version.</div>
        </Panel>
      </div>

      <Panel title="Identified database services" aside={dbAssets.length > DETAIL_CAP ? `version read for the first ${DETAIL_CAP} assets` : undefined}>
        <QueryState loading={ports.isLoading} error={ports.error} what="open ports" />
        {ports.data && (
          <TableWrap>
            <table className="disc-table">
              <thead><tr><th>Asset</th><th>Engine</th><th>Port</th><th>Product</th><th>Version</th><th className="hide-sm">Identified by</th><th>Last seen</th></tr></thead>
              <tbody>
                {dbs.map((p) => {
                  const s = svc(p);
                  return (
                    <tr key={`${p.asset_id}-${p.port}`}>
                      <td><AssetRef a={p} /></td>
                      <td>{DB_ENGINES[p.service!].label}</td>
                      <td className="data">{p.port}/{p.protocol}</td>
                      <td>{p.product || <span className="unknown">not reported</span>}</td>
                      <td>{s?.version ? <span className="data">{s.version}{s.version_confidence != null && <span className="faint"> · {s.version_confidence.toFixed(2)}</span>}</span> : <span className="unknown">{s ? "not reported" : "…"}</span>}</td>
                      <td className="muted hide-sm">{s?.method ?? "—"}</td>
                      <td className="data">{ago(p.last_seen)}</td>
                    </tr>
                  );
                })}
                {dbs.length === 0 && <tr className="empty"><td colSpan={7}>No database service has been identified{partial}. A fingerprint scan identifies MySQL in safe mode; PostgreSQL and SQL Server need an intrusive one.</td></tr>}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Panel>

      <Panel title="Open on a database port, not identified" aside={<Pager page={page} total={onDbPorts.length} onPage={setPage} />}>
        {ports.data && (
          <TableWrap>
            <table className="disc-table">
              <thead><tr><th>Asset</th><th>Port</th><th>Engine's port</th><th>State</th><th>Last seen</th></tr></thead>
              <tbody>
                {onDbPorts.slice(page * PAGE_ROWS, (page + 1) * PAGE_ROWS).map((p) => (
                  <tr key={`${p.asset_id}-${p.port}`}>
                    <td><AssetRef a={p} /></td>
                    <td className="data">{p.port}/{p.protocol}</td>
                    <td className="muted">{DB_ENGINES[dbEngineForPort(p.port)!].label}</td>
                    <td><PortStateChip state={portState(p)} /></td>
                    <td className="data">{ago(p.last_seen)}</td>
                  </tr>
                ))}
                {onDbPorts.length === 0 && <tr className="empty"><td colSpan={5}>No unidentified open port{partial} is on a database engine's port.</td></tr>}
              </tbody>
            </table>
          </TableWrap>
        )}
        <div className="foot-note">
          These are ports, not databases: the port number is the engine's, but nothing has confirmed what is listening.
          {ports.data?.truncated && <> The open-port read returns the {ports.data.limit} most recently seen ports, so these lists are partial.</>} Assets with no current address are shown by the first characters of their id.
        </div>
      </Panel>
    </section>
  );
}
