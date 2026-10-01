import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, has } from "../lib/api";
import { useAuth } from "../lib/auth";
import { PageHead } from "../components/PageHead";
import { HBars } from "../components/Charts";
import { AssetRef, Gap, Metric, Pager, PAGE_ROWS, Panel, PortStateChip, PortStateDonut, QueryState, TableWrap } from "../components/Discovery";
import { ago } from "../lib/console";
import {
  countBy, HTTPS_PROBE_PORTS, HTTP_PROBE_PORTS, isHttpService, plural, portState, PORT_STATE_ORDER, PORT_STATES, WEB_PROBE_PORTS,
} from "../lib/discovery";

// Web & API Discovery, as far as Core can take it today. Core identifies an
// HTTP service by probing it — HTTP volunteers nothing, so only an intrusive
// fingerprint scan can — and records the server product from its Server
// header. It does not crawl, enumerate endpoints, read OpenAPI documents or
// distinguish virtual hosts. This page shows the real part and names the
// rest, rather than drawing a web inventory nobody collected.
const CAPABILITIES: { state: "ok" | "warn" | "muted"; chip: string; what: string; detail: string }[] = [
  { state: "ok", chip: "available", what: "HTTP service identification", detail: "HEAD probes on the ports below; intrusive fingerprint scans only — in safe mode a web server is an open port with no service" },
  { state: "ok", chip: "available", what: "Server product", detail: "nginx, Apache httpd and Microsoft IIS, from the Server header" },
  { state: "warn", chip: "recorded, not served", what: "TLS certificates", detail: "fingerprint scans record subject, issuer, validity and SANs; no API route returns them yet" },
  { state: "muted", chip: "not available", what: "URL and path discovery", detail: "Core does not crawl" },
  { state: "muted", chip: "not available", what: "API endpoints, OpenAPI / Swagger", detail: "no endpoint enumeration or specification discovery" },
  { state: "muted", chip: "not available", what: "Virtual hosts", detail: "TLS SNI is the scanned address, so name-based sites are not told apart" },
  { state: "muted", chip: "not stored", what: "Page titles and response headers", detail: "kept only as finding evidence, not as inventory" },
  { state: "muted", chip: "out of scope", what: "DAST and API testing", detail: "outside the current build" },
];

export function WebDiscovery() {
  const { session } = useAuth();
  const canAssets = has(session, "asset.read");
  const ports = useQuery({ queryKey: ["open-ports"], queryFn: () => api.openPorts(), enabled: canAssets });
  const [page, setPage] = useState(0);

  const all = ports.data?.ports ?? [];
  // Every row that is HTTP by identification, plus every row on a port the
  // HTTP probes target whatever its state — the second set is "where a web
  // server would be found", and is labelled by state, never as a web server.
  const rows = all
    .filter((p) => isHttpService(p.service) || WEB_PROBE_PORTS.includes(p.port))
    .sort((a, b) => PORT_STATE_ORDER.indexOf(portState(a)) - PORT_STATE_ORDER.indexOf(portState(b)) || a.port - b.port || b.last_seen.localeCompare(a.last_seen));
  const http = rows.filter((p) => isHttpService(p.service));
  const onHttp = rows.filter((p) => HTTP_PROBE_PORTS.includes(p.port));
  const onHttps = rows.filter((p) => HTTPS_PROBE_PORTS.includes(p.port));
  const unidentified = rows.filter((p) => portState(p) !== "recognised");
  const products = countBy(http.filter((p) => p.product), (p) => p.product!);
  const byPort = Object.entries(countBy(rows, (p) => `${p.port}/${p.protocol}`)).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const partial = ports.data?.truncated ? ` among the ${ports.data.limit} most recently seen open ports` : "";

  return (
    <section className="discover">
      <PageHead
        title="Web & API Discovery"
        sub="HTTP services Core has identified, and the open ports where its HTTP probes look. Core identifies web servers; it does not yet crawl them, enumerate API endpoints or read API specifications."
        meta={ports.data ? `${plural(rows.length, "web-probe port")}${ports.data.truncated ? " · partial" : ""}` : ""}
      />
      {!canAssets && <Gap>This page reads open ports, which this session's permissions do not include.</Gap>}

      <div className="metric-strip">
        <Metric label="HTTP services identified" value={ports.data ? http.length : "—"} tone={ports.data && http.length > 0 ? "ok" : undefined}
                qual={ports.data ? plural(new Set(http.map((p) => p.asset_id)).size, "asset") : undefined}
                foot={ports.data ? (http.length ? Object.keys(products).join(" · ") || "product not reported" : `none${partial}`) : "recognised by an HTTP probe"} />
        <Metric label="Open on HTTP probe ports" value={ports.data ? onHttp.length : "—"} qual={ports.data ? plural(new Set(onHttp.map((p) => p.asset_id)).size, "asset") : undefined}
                foot="80, 8080, 8000, 8888 and 7 more" />
        <Metric label="Open on HTTPS probe ports" value={ports.data ? onHttps.length : "—"} qual={ports.data ? plural(new Set(onHttps.map((p) => p.asset_id)).size, "asset") : undefined}
                foot="443, 8443, 4443, 9443, 10443" />
        <Metric label="Not identified" value={ports.data ? unidentified.length : "—"} tone={unidentified.length ? "warn" : undefined}
                qual={ports.data ? `of ${rows.length}` : undefined} foot="on a web probe port, no service recognised" />
      </div>

      <div className="disc-grid-3">
        <Panel title="Identification on web probe ports" aside={ports.data?.truncated ? `${ports.data.limit} most recent` : undefined}>
          <QueryState loading={ports.isLoading} error={ports.error} what="open ports" />
          {ports.data && (rows.length ? <PortStateDonut states={rows.map(portState)} /> : <p className="empty">No open port{partial} is on a port the HTTP probes target.</p>)}
        </Panel>
        <Panel title="Web probe ports by state" aside="open ports per port number">
          {ports.data && (byPort.length ? (
            <HBars unit="open ports" rows={byPort.map(([key]) => ({
              key, label: key,
              segments: PORT_STATE_ORDER.map((st) => ({ key: st, label: PORT_STATES[st].label, tone: PORT_STATES[st].tone, value: rows.filter((p) => `${p.port}/${p.protocol}` === key && portState(p) === st).length })),
            }))} />
          ) : <p className="empty">Nothing to chart.</p>)}
        </Panel>
        <Panel title="Capability" aside="what this page can and cannot show" className="disc-capability">
          <ul className="cap-list">
            {CAPABILITIES.map((c) => (
              <li key={c.what} title={c.detail}><span className={`chip chip-${c.state}`}>{c.chip}</span> {c.what}</li>
            ))}
          </ul>
        </Panel>
      </div>

      <div className="disc-main">
        <Panel title="Web probe ports" aside={<Pager page={page} total={rows.length} onPage={setPage} />}>
          <QueryState loading={ports.isLoading} error={ports.error} what="open ports" />
          {ports.data && (
            <TableWrap>
              <table className="disc-table">
                <thead><tr><th>Asset</th><th>Port</th><th>State</th><th>Service</th><th>Last seen</th></tr></thead>
                <tbody>
                  {rows.slice(page * PAGE_ROWS, (page + 1) * PAGE_ROWS).map((p) => (
                    <tr key={`${p.asset_id}-${p.port}-${p.protocol}`}>
                      <td><AssetRef a={p} /></td>
                      <td className="data">{p.port}/{p.protocol}</td>
                      <td><PortStateChip state={portState(p)} /></td>
                      <td>{p.service ? <span className="data">{p.service}{p.product ? ` · ${p.product}` : ""}</span> : <span className="unknown">—</span>}</td>
                      <td className="data">{ago(p.last_seen)}</td>
                    </tr>
                  ))}
                  {rows.length === 0 && <tr className="empty"><td colSpan={5}>No open port{partial} is on a web probe port or identified as HTTP.</td></tr>}
                </tbody>
              </table>
            </TableWrap>
          )}
          <div className="foot-note">
            A port listed here is where an HTTP server would be found, not proof of one: only a recognised state means a probe identified HTTP.
            An intrusive fingerprint scan of the unidentified ones is what would tell. {ports.data?.truncated && <>The open-port read returns the {ports.data.limit} most recently seen ports, so these counts are partial.</>} Assets with no current address are shown by the first characters of their id.
          </div>
        </Panel>
        <div className="stack">
          <Panel title="What would fill this page">
            <ul className="cap-list cap-detail">
              {CAPABILITIES.filter((c) => c.state !== "ok").map((c) => (
                <li key={c.what}><b>{c.what}</b><span className="muted"> — {c.detail}.</span></li>
              ))}
            </ul>
            <div className="foot-note">Related: <Link to="/discover/discovery/unknown-assets">Unknown Assets</Link> lists every unidentified open port.</div>
          </Panel>
        </div>
      </div>
    </section>
  );
}
