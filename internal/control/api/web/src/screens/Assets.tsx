import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { ExportButton } from "../components/ExportButton";
import { PageHead } from "../components/PageHead";
import { SegmentBar } from "../components/Charts";
import { advisory } from "../lib/console";

// The inventory, ordered by risk: which SYSTEM is vulnerable is the row's own
// question now. Every row carries its open-finding count, the worst severity
// on it, its KEV count and its advisory posture — all served by Core from the
// same finding rows the triage list pages over, never computed here.
const PAGE = 200;

export function Assets() {
  const [q, setQ] = useState("");
  const [environment, setEnvironment] = useState("");
  const [view, setView] = useState<"risk" | "all">("risk");

  const qs = new URLSearchParams();
  if (q) qs.set("q", q);
  if (environment) qs.set("environment", environment);
  qs.set("sort", "risk");
  if (view === "risk") qs.set("at_risk", "true");
  qs.set("limit", String(PAGE));
  const query = `?${qs}`;

  const { data, isLoading, error } = useQuery({ queryKey: ["assets", query], queryFn: () => api.listAssets(query) });
  const rows = data?.assets ?? [];
  const posture = ["vulnerable", "cannot_know", "no_release", "clean"].map((k) => ({
    key: k, label: advisory(k).label, tone: advisory(k).tone, value: rows.filter((a) => a.advisory_status === k).length,
  }));

  return (
    <section>
      <PageHead
        title="Systems"
        sub="Ordered by risk: KEV-listed findings first, then the worst severity present, then how many are open. The posture word is the server's verdict; an empty finding list is never called clean."
        action={<ExportButton perm="asset.export_all" href={api.exportURL("assets", `?${new URLSearchParams(q ? { q } : {})}`)} />}
      />
      <div className="triage-filters">
        <button className={`filt${view === "risk" ? " on" : ""}`} onClick={() => setView("risk")}>with open findings</button>
        <button className={`filt${view === "all" ? " on" : ""}`} onClick={() => setView("all")}>every system</button>
        <span className="vsep" />
        <input placeholder="environment" value={environment} onChange={(e) => setEnvironment(e.target.value)} style={{ marginLeft: 0, width: 140 }} aria-label="environment" />
        <input placeholder="hostname or address…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="search" />
      </div>
      {data && rows.length > 0 && (
        <div className="triage-strip">
          <SegmentBar segments={posture} height={8} caption={`${rows.length} system${rows.length === 1 ? "" : "s"} shown${data.next_id ? ", more exist" : ""} · advisory posture`} />
          <span className="kevcount"><b>{rows.reduce((n, a) => n + a.open_findings, 0)}</b> open findings · <b>{rows.filter((a) => a.kev_findings > 0).length}</b> systems with KEV</span>
        </div>
      )}
      {isLoading && <p className="muted">Loading…</p>}
      {error && <p className="error">Could not load systems.</p>}
      {data && (
        <table>
          <thead>
            <tr>
              <th>System</th><th>Posture</th><th className="num">Open</th><th>Worst</th><th className="num">KEV</th>
              <th>OS</th><th>Environment</th><th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((a) => {
              const p = advisory(a.advisory_status);
              return (
                <tr key={a.id} className={`frow frow-${a.worst_severity || "info"}`}>
                  <td>
                    <Link to={`/assets/${a.id}`} className="data">{a.hostname || a.address || a.id.slice(0, 8)}</Link>
                    {a.hostname && a.address && <span className="faint small"> · {a.address}</span>}
                    {a.fragile && <span className="chip chip-high" style={{ marginLeft: ".4rem" }}>fragile</span>}
                  </td>
                  <td><span className={`chip chip-${p.tone === "critical" ? "danger" : p.tone}`} title={p.why}>{p.label}</span></td>
                  <td className="num">{a.open_findings || <span className="faint">0</span>}</td>
                  <td>{a.worst_severity ? <span className={`sev sev-${a.worst_severity}`}>{a.worst_severity}</span> : <span className="faint">—</span>}</td>
                  <td className="num">{a.kev_findings ? <span className="kev-badge">{a.kev_findings}</span> : <span className="faint">0</span>}</td>
                  <td>{a.os_family || <span className="unknown">unknown</span>}</td>
                  <td className="muted">{a.environment || "—"}</td>
                  <td className="data">{fmt(a.last_seen)}</td>
                </tr>
              );
            })}
            {rows.length === 0 && (
              <tr className="empty"><td colSpan={8}>{view === "risk" ? "No system has an open finding. Switch to every system to see the inventory, or check Knowledge: a stale feed or an out-of-coverage release makes silence mean cannot-know, not clean." : "No systems match."}</td></tr>
            )}
          </tbody>
        </table>
      )}
    </section>
  );
}
function fmt(t?: string): string { return t ? new Date(t).toLocaleString() : "—"; }
