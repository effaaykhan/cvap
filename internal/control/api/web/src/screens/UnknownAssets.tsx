import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, has } from "../lib/api";
import { useAuth } from "../lib/auth";
import { PageHead } from "../components/PageHead";
import { Donut } from "../components/Charts";
import { AssetRef, Gap, Metric, Pager, PAGE_ROWS, Panel, PortStateChip, PortStateDonut, QueryState, TableWrap } from "../components/Discovery";
import { ago, groupPorts } from "../lib/console";
import { plural, portState } from "../lib/discovery";

// Unknown Assets: the places where Core's picture of the estate is incomplete,
// each under its own name, because they are four different things —
//   * an address whose PRESENCE is unknown (answered, proved nothing),
//   * an address suppressed as a RESPONDER (one device answering for a range),
//   * an open port nothing has IDENTIFIED,
//   * an address whose IDENTITY is contested and waits for an operator.
// None of them is called an "unknown asset" on its own: an asset is only what
// correlation concluded, and these are the evidence it could not conclude from.
export function UnknownAssets() {
  const { session } = useAuth();
  const canAssets = has(session, "asset.read");
  const canScans = has(session, "scan.read");
  // A one-row asset read: only for the estate-wide presence totals it carries.
  const presenceQ = useQuery({ queryKey: ["assets", "?limit=1"], queryFn: () => api.listAssets("?limit=1"), enabled: canAssets });
  const ports = useQuery({ queryKey: ["open-ports"], queryFn: () => api.openPorts(), enabled: canAssets });
  const queue = useQuery({ queryKey: ["identity-queue", "discover"], queryFn: () => api.identityQueue("", undefined, 6), enabled: canAssets });
  const health = useQuery({ queryKey: ["health"], queryFn: () => api.health(), enabled: canScans });
  const [page, setPage] = useState(0);

  const presence = presenceQ.data?.address_presence;
  const all = ports.data?.ports ?? [];
  const unidentified = all.filter((p) => portState(p) !== "recognised");
  // Assets on which no open port was recognised at all: nothing has said what
  // they are. Grouped so each asset is one row with its ports beside it.
  const groups = groupPorts(all, (p) => p.asset_id).filter(([, rows]) => rows.every((p) => portState(p) !== "recognised"));
  const partial = ports.data?.truncated ? ` among the ${ports.data.limit} most recently seen open ports` : "";

  return (
    <section className="discover">
      <PageHead
        title="Unknown Assets"
        sub="Where Core's view of the estate is incomplete: addresses whose presence is unproven, open ports nothing has identified, and identities waiting on an operator. Each is a different kind of unknown and is named as such."
      />
      {!canAssets && <Gap>This page reads assets and open ports, which this session's permissions do not include.</Gap>}

      <div className="metric-strip">
        <Metric label="Presence unknown" value={presence ? presence.unknown : "—"} qual={presence ? `of ${presence.total} live addresses` : undefined}
                tone={presence && presence.unknown > 0 ? "warn" : undefined}
                foot={presence ? (presence.total === 0 ? "no asset currently holds a live address" : "answered, proved nothing either way") : "address presence verdicts"} />
        <Metric label="Unidentified open ports" value={ports.data ? `${unidentified.length}${ports.data.truncated ? "+" : ""}` : "—"}
                qual={ports.data ? plural(new Set(unidentified.map((p) => p.asset_id)).size, "asset") : undefined}
                tone={unidentified.length ? "warn" : undefined}
                foot={ports.data?.truncated ? `of the ${ports.data.limit} most recently seen` : "no service recognised"} />
        <Metric label="Contested identities" value={queue.data ? queue.data.addresses_total : "—"} qual={queue.data ? "addresses" : undefined}
                tone={queue.data && queue.data.addresses_total > 0 ? "warn" : undefined}
                foot={queue.data ? (queue.data.addresses_total ? <Link to="/identity">awaiting an operator ruling →</Link> : "nothing waits on a ruling") : "identity queue"} />
        <Metric label="Unresolved observations" value={health.data ? health.data.unresolved_observations : "—"}
                tone={health.data && health.data.unresolved_observations > 0 ? "warn" : undefined}
                foot={canScans ? "accepted in the last 7 days, on no asset yet" : "needs scan.read"} />
      </div>

      <div className="disc-grid-3">
        <Panel title="Address presence" aside="current addresses, by verdict">
          <QueryState loading={presenceQ.isLoading} error={presenceQ.error} what="address presence" />
          {presence && (presence.total > 0 ? (
            <>
              <Donut center="addresses" segments={[
                { key: "present", label: "present", tone: "ok", value: presence.present },
                { key: "unknown", label: "presence unknown", tone: "warn", value: presence.unknown },
                { key: "responder", label: "responder (suppressed)", tone: "muted", value: presence.responder },
              ]} />
              <p className="disc-statement">{presence.statement}</p>
            </>
          ) : (
            <p className="empty">No asset currently holds a live address, so there is no presence verdict to show. Verdicts apply to current addresses only.</p>
          ))}
        </Panel>
        <Panel title="Open-port identification" aside={ports.data?.truncated ? `${ports.data.limit} most recent` : undefined}>
          <QueryState loading={ports.isLoading} error={ports.error} what="open ports" />
          {ports.data && (all.length ? <PortStateDonut states={all.map(portState)} /> : <p className="empty">No open port is recorded.</p>)}
        </Panel>
        <Panel title="Identity queue" aside={<Link to="/identity">open queue →</Link>}>
          <QueryState loading={queue.isLoading} error={queue.error} what="the identity queue" />
          {queue.data && (queue.data.groups.length ? (
            <div className="attn">
              {queue.data.groups.map((g) => (
                <div className="item" key={g.address}>
                  <span className="dot dot-warn" />
                  <span>
                    <span className="data">{g.address}</span> <span className="muted">· {g.reason}</span>
                    <span className="detail"> — {plural(g.items_total, "observation")}, {plural(g.candidates.length, "candidate asset")}, last {ago(g.last_seen)}</span>
                  </span>
                </div>
              ))}
              {queue.data.addresses_total > queue.data.groups.length && <span className="faint small">and {queue.data.addresses_total - queue.data.groups.length} more</span>}
            </div>
          ) : <p className="empty">Nothing is contested. Correlation has attached every address it was given.</p>)}
        </Panel>
      </div>

      <div className="disc-main">
        <Panel title="Assets with no recognised service" aside={<Pager page={page} total={groups.length} onPage={setPage} />}>
          <QueryState loading={ports.isLoading} error={ports.error} what="open ports" />
          {ports.data && (
            <TableWrap>
              <table className="disc-table">
                <thead><tr><th>Asset</th><th>Open ports</th><th>State</th><th className="hide-sm">Last seen</th></tr></thead>
                <tbody>
                  {groups.slice(page * PAGE_ROWS, (page + 1) * PAGE_ROWS).map(([id, rows]) => {
                    const answered = rows.filter((p) => portState(p) === "answered").length;
                    const last = rows.reduce((m, p) => (p.last_seen > m ? p.last_seen : m), rows[0].last_seen);
                    return (
                      <tr key={id}>
                        <td><AssetRef a={rows[0]} /></td>
                        <td className="data unknown">{rows.map((p) => `${p.port}/${p.protocol}`).join(", ")}</td>
                        <td>{answered === rows.length ? <PortStateChip state="answered" /> : answered === 0 ? <PortStateChip state="probed" /> : <span className="muted small">{answered} unidentified · {rows.length - answered} no match</span>}</td>
                        <td className="data hide-sm">{ago(last)}</td>
                      </tr>
                    );
                  })}
                  {groups.length === 0 && <tr className="empty"><td colSpan={4}>Every asset with an open port{partial} has at least one recognised service.</td></tr>}
                </tbody>
              </table>
            </TableWrap>
          )}
          <div className="foot-note">
            Open ports answered, but no banner or probe said what is listening — so Core knows these assets exist and little else.
            A fingerprint scan identifies them; HTTP, PostgreSQL and SQL Server need an intrusive one.
            {ports.data?.truncated && <> Built from the {ports.data.limit} most recently seen open ports; an asset may have recognised services outside them.</>} Assets with no current address are shown by the first characters of their id.
          </div>
        </Panel>
        <div className="stack">
          <Panel title="Terms on this page">
            <dl className="disc-terms">
              <dt><span className="cdot tone-warn" /> Presence unknown</dt>
              <dd>The address answered, but nothing identified itself and it shows no responder signature. Not convicted, not confirmed.</dd>
              <dt><span className="cdot tone-muted" /> Responder</dt>
              <dd>Answers that look like one device replying for a whole range, or a network or broadcast address. Suppressed, not deleted.</dd>
              <dt><span className="cdot tone-warn" /> Unidentified port</dt>
              <dd>A discovery scan saw the port accept a connection; nothing has said what is listening.</dd>
              <dt><span className="cdot tone-muted" /> Probed, no match</dt>
              <dd>A fingerprint attempt reached the port and no identification rule matched its reply.</dd>
              <dt><span className="cdot tone-warn" /> Contested identity</dt>
              <dd>An address whose evidence contradicts the asset holding it — for example a changed host key or certificate — parked for an operator.</dd>
            </dl>
          </Panel>
          {health.data && (
            <Panel title="Correlation backlog" aside={<Link to="/health">health →</Link>}>
              <div className="change-tiles disc-tiles-3">
                <div className={`change-tile${health.data.unresolved_observations ? " warn" : ""}`}><div className="n">{health.data.unresolved_observations}</div><div className="k">unresolved obs.</div></div>
                <div className={`change-tile${health.data.resolution_queue_pending ? " warn" : ""}`}><div className="n">{health.data.resolution_queue_pending}</div><div className="k">queue items</div></div>
                <div className={`change-tile${health.data.contested_addresses ? " warn" : ""}`}><div className="n">{health.data.contested_addresses}</div><div className="k">contested addr.</div></div>
              </div>
            </Panel>
          )}
          <Gap>Each address's own presence verdict and its reason are recorded, but the API serves only the totals, so addresses cannot be listed by verdict here.</Gap>
        </div>
      </div>
    </section>
  );
}
