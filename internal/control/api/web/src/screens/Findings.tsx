import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, type FindingSummary } from "../lib/api";
import { ExportButton } from "../components/ExportButton";
import { PageHead } from "../components/PageHead";
import { applyTriageFilter, attackCell, confidenceBand, score, type TriageFilter } from "../lib/console";

const STATUSES = ["open", "confirmed", "", "false_positive", "accepted_risk", "remediated", "closed"];
const PAGE = 200;

// Findings triage (console rung 3): the priority-ordered table with the
// finding-row signature, KEV as the loudest chip, EPSS/CVSS as mono values with
// a dash for unscored, confidence as a lane, and the evidence one click away.
export function Findings() {
  const [status, setStatus] = useState("open");
  const [severity, setSeverity] = useState("");
  const [filter, setFilter] = useState<TriageFilter>({ kevOnly: false, band: "", q: "" });

  const qs = new URLSearchParams();
  if (status) qs.set("status", status);
  if (severity) qs.set("severity", severity);
  qs.set("limit", String(PAGE));
  const query = `?${qs}`;

  const { data, isLoading, error } = useQuery({
    queryKey: ["findings", query],
    queryFn: () => api.listFindings(query),
  });

  const rows = data ? applyTriageFilter(data.findings, filter) : [];
  const truncated = data?.next_id != null;
  const counts = ["critical", "high", "medium", "low", "info"].map((k) => ({
    key: k, value: rows.filter((f) => f.severity === k).length,
  }));
  const kevShown = rows.filter((f) => f.kev).length;

  return (
    <section>
      <PageHead
        title="Findings triage"
        sub={
          data ? (
            <>
              {data.findings.length}{truncated ? "+" : ""} {status || "in any status"} · ordered by priority, not severity
              {truncated && <> · showing the first {PAGE}; narrow with the filters</>}
            </>
          ) : undefined
        }
        action={<ExportButton perm="finding.export_all" href={api.exportURL("findings", `?${new URLSearchParams(status ? { status } : {})}`)} />}
      />

      <div className="triage-filters">
        {STATUSES.slice(0, 2).map((s) => (
          <button key={s} className={`filt${status === s ? " on" : ""}`} onClick={() => setStatus(s)}>{s}</button>
        ))}
        <select value={STATUSES.slice(0, 2).includes(status) ? "" : status} onChange={(e) => setStatus(e.target.value)} aria-label="other status">
          <option value="">other status…</option>
          {STATUSES.slice(2).map((s) => (
            <option key={s} value={s}>{s || "any status"}</option>
          ))}
        </select>
        <span className="vsep" />
        <button className={`filt${filter.kevOnly ? " on" : ""}`} onClick={() => setFilter({ ...filter, kevOnly: !filter.kevOnly })}>KEV only</button>
        <button
          className={`filt${filter.band ? " on" : ""}`}
          onClick={() => setFilter({ ...filter, band: filter.band ? "" : "critical+high" })}
        >
          critical+high
        </button>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="severity">
          <option value="">any severity</option>
          {["critical", "high", "medium", "low", "info"].map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <input placeholder="asset, CVE or rule…" value={filter.q} onChange={(e) => setFilter({ ...filter, q: e.target.value })} aria-label="search" />
      </div>

      {isLoading && <p className="muted">Loading…</p>}
      {error && <p className="error">Could not load findings.</p>}
      {data && rows.length > 0 && (
        <div className="triage-strip">
          <div className="sev-counts" role="group" aria-label="shown by severity">
            {counts.map((c) => (
              <span key={c.key} className={`sev-count sev-${c.key}${c.value === 0 ? " zero" : ""}`}>
                <span className="k">{c.key}</span><b>{c.value}</b>
              </span>
            ))}
            <span className="shown">{rows.length} shown{truncated ? ` of the first ${PAGE}` : ""}</span>
          </div>
          <span className="kevcount"><b>{kevShown}</b> in KEV · <b>{rows.filter((f) => f.epss != null && f.epss >= 0.5).length}</b> with EPSS ≥ 0.5</span>
        </div>
      )}
      {data && (
        <table>
          <thead>
            <tr>
              <th>Priority</th><th>Severity</th><th>Finding</th><th>ATT&amp;CK</th><th>Asset</th><th>Where</th>
              <th>Confidence</th><th className="num">EPSS</th><th className="num">CVSS</th><th>Exposure</th><th>Status</th><th />
            </tr>
          </thead>
          <tbody>
            {rows.map((f) => (
              <Row key={f.id} f={f} rank={f.rank} />
            ))}
            {rows.length === 0 && (
              <tr className="empty"><td colSpan={12}>{data.findings.length ? "No findings match these filters within this page." : "No findings match these filters."}</td></tr>
            )}
          </tbody>
        </table>
      )}

      <div className="legend">
        <span className="lbl">confidence</span>
        <span className="lane"><span className="cdot cdot-high" />high ≥ 0.85</span>
        <span className="lane"><span className="cdot cdot-medium" />medium ≥ 0.60</span>
        <span className="lane"><span className="cdot cdot-low" />low</span>
      </div>
    </section>
  );
}

function Row({ f, rank }: { f: FindingSummary; rank: number }) {
  const band = confidenceBand(f.confidence);
  // ATT&CK is context beside the ranking, never inside it (ADR-105 decision
  // 5): the cell sits next to the finding it qualifies, and nothing sorts,
  // weights or colours by it.
  const atk = attackCell(f.attack_techniques);
  return (
    <tr className={`frow frow-${f.severity}`}>
        <td>
          <span className="rank">#{rank}</span>
          {f.kev && (
            <span className={`kev-badge${f.kev_ransomware ? " kev-ransomware" : ""}`}
                  title={f.kev_ransomware ? "CISA KEV — known ransomware use" : "CISA KEV — known exploited"}>
              KEV
            </span>
          )}{" "}
          <span className={`priority-basis${f.priority_basis === "unscored" ? " muted" : ""}`}>{f.priority_basis}</span>
        </td>
        <td><span className={`sev sev-${f.severity}`}>{f.severity}</span></td>
        <td className="finding-cell" title={`${f.rule} · ${f.category}`}>
          <Link to={`/findings/${f.id}`} className={f.cve ? "data" : undefined}>{f.cve || f.rule}</Link>
          <span className="cat small">{f.cve ? "vulnerability" : "configuration"}</span>
        </td>
        <td
          className={`attack-cell${atk.unmapped ? " unmapped" : ""}`}
          title={atk.unmapped
            ? "CVAP holds no ATT&CK mapping for this finding — not a claim that no technique applies"
            : `inferred, not observed: ${f.attack_techniques.map((t) => `${t.id} ${t.name}`).join(", ")}`}
        >
          {atk.unmapped ? atk.text : <span className="data">{atk.text}</span>}
        </td>
        <td className="data">{f.asset_hostname || f.asset_id}</td>
        <td className="data">{f.instance_locator || "—"}</td>
        <td>
          <span className={`lane conf-${band}`} title={`confidence ${Math.round((f.confidence ?? 0) * 100)}%`}>
            <span className={`cdot cdot-${band}`} />{band}<span className="val">{(f.confidence ?? 0).toFixed(2)}</span>
          </span>
        </td>
        <td className={`num${(f.epss ?? 0) >= 0.5 ? " hot" : ""}`}>{score(f.epss, 5)}</td>
        <td className="num">{score(f.cvss, 1)}</td>
        <td className="exposure-cell">{f.exposure_zones} zone{f.exposure_zones === 1 ? "" : "s"}</td>
        <td className="muted">{f.status}</td>
        <td className="expand">
          <Link to={`/findings/${f.id}`} aria-label="open finding" title="open finding">›</Link>
        </td>
      </tr>
  );
}
