import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, type FindingSummary } from "../lib/api";
import { ExportButton } from "../components/ExportButton";
import { EvidenceBlock } from "../components/Evidence";
import { PageHead } from "../components/PageHead";
import { applyTriageFilter, confidenceBand, score, type TriageFilter } from "../lib/console";

const STATUSES = ["open", "confirmed", "", "false_positive", "accepted_risk", "remediated", "closed"];
const PAGE = 200;

// Findings triage (console rung 3): the priority-ordered table with the
// finding-row signature, KEV as the loudest chip, EPSS/CVSS as mono values with
// a dash for unscored, confidence as a lane, and the evidence one click away.
export function Findings() {
  const [status, setStatus] = useState("open");
  const [severity, setSeverity] = useState("");
  const [filter, setFilter] = useState<TriageFilter>({ kevOnly: false, band: "", q: "" });
  const [open, setOpen] = useState<string | null>(null);

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
      {data && (
        <table>
          <thead>
            <tr>
              <th>Priority</th><th>Severity</th><th>Finding</th><th>Asset</th><th>Where</th>
              <th>Confidence</th><th className="num">EPSS</th><th className="num">CVSS</th><th>Exposure</th><th>Status</th><th />
            </tr>
          </thead>
          <tbody>
            {rows.map((f) => (
              <Row key={f.id} f={f} rank={f.rank} open={open === f.id} onToggle={() => setOpen(open === f.id ? null : f.id)} />
            ))}
            {rows.length === 0 && (
              <tr className="empty"><td colSpan={11}>{data.findings.length ? "No findings match these filters within this page." : "No findings match these filters."}</td></tr>
            )}
          </tbody>
        </table>
      )}

      <div className="legend">
        <span className="lbl">confidence</span>
        <span className="lane"><span className="cdot cdot-high" />high ≥ 0.85</span>
        <span className="lane"><span className="cdot cdot-medium" />medium ≥ 0.60</span>
        <span className="lane"><span className="cdot cdot-low" />low</span>
        <span className="end">a dash in EPSS or CVSS is unscored, never 0 · exposure is zone-derived, a coarse count of vantage points, not reachability</span>
      </div>
    </section>
  );
}

function Row({ f, rank, open, onToggle }: { f: FindingSummary; rank: number; open: boolean; onToggle: () => void }) {
  const band = confidenceBand(f.confidence);
  return (
    <>
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
        <td className="finding-cell"><Link to={`/findings/${f.id}`}>{f.rule}</Link><span className="cat small">{f.category}</span></td>
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
          <button onClick={onToggle} aria-expanded={open} aria-label={open ? "hide evidence" : "show evidence"} title="evidence">{open ? "▾" : "›"}</button>
        </td>
      </tr>
      {open && <EvidenceRow id={f.id} />}
    </>
  );
}

// Evidence one click away: the row fetches the finding it expands, so the
// analyst confirms the claim without leaving the table or re-scanning.
function EvidenceRow({ id }: { id: string }) {
  const { data: f, isLoading, error } = useQuery({ queryKey: ["finding", id], queryFn: () => api.getFinding(id) });
  return (
    <tr className="evidence-row">
      <td colSpan={11}>
        <span className="lbl">Evidence — confirm without re-scanning</span>
        {isLoading && <p className="muted">Loading…</p>}
        {error && <p className="error">Could not load this finding's evidence.</p>}
        {f && (
          <>
            <div className="evidence-facts">
              <div><div className="k">claim</div><div className="v">{f.has_vuln_def ? "advisory-matched" : "rule / banner-inferred"}</div></div>
              <div><div className="k">source</div><div className="v">{f.source}</div></div>
              <div><div className="k">exploitation</div><div className="v">{f.kev ? `KEV${f.kev_date_added ? ` · added ${f.kev_date_added}` : ""}` : "not listed in KEV (unlisted, not known-unexploited)"}</div></div>
              <div><div className="k">basis</div><div className="v">{f.priority_basis}</div></div>
            </div>
            <EvidenceBlock evidence={f.evidence ?? []} />
            <p className="provenance"><Link to={`/findings/${f.id}`}>Open the full finding →</Link></p>
          </>
        )}
      </td>
    </tr>
  );
}
