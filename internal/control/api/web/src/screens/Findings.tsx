import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, type FindingSummary } from "../lib/api";
import { ExportButton } from "../components/ExportButton";
import { Confidence } from "../components/Confidence";

const SEVERITIES = ["", "critical", "high", "medium", "low", "info"];
const STATUSES = ["", "open", "confirmed", "false_positive", "accepted_risk", "remediated", "closed"];

// EPSS is nullable-shaped: null/undefined means UNSCORED (no signal), never a
// probability of 0 (ADR-069). A dash says "unscored"; 0.00 would be a lie.
function epssText(epss: number | null | undefined): string {
  return epss == null ? "—" : epss.toFixed(5);
}

// The priority cell makes the order legible rather than a black box (ADR-069):
// a KEV badge when listed (ransomware-linked KEV entries are flagged harder),
// and the basis naming the dominant reason. A finding with neither EPSS nor
// CVSS reads "unscored" — no-signal, distinct from a low value.
function PriorityCell({ f }: { f: FindingSummary }) {
  return (
    <span className="priority-cell">
      {f.kev && (
        <span className={`kev-badge${f.kev_ransomware ? " kev-ransomware" : ""}`}
              title={f.kev_ransomware ? "CISA KEV — known ransomware use" : "CISA KEV — known exploited"}>
          KEV
        </span>
      )}
      <span className={`priority-basis${f.priority_basis === "unscored" ? " muted" : ""}`}>
        {f.priority_basis}
      </span>
    </span>
  );
}

export function Findings() {
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");

  const qs = new URLSearchParams();
  if (status) qs.set("status", status);
  if (severity) qs.set("severity", severity);
  const query = qs.toString() ? `?${qs}` : "";

  const { data, isLoading, error } = useQuery({
    queryKey: ["findings", query],
    queryFn: () => api.listFindings(query),
  });

  return (
    <section>
      <div className="row-between">
        <h1>Findings</h1>
        <ExportButton perm="finding.export_all" href={api.exportURL("findings", query)} />
      </div>
      <div className="filters">
        <select value={status} onChange={(e) => setStatus(e.target.value)}>
          {STATUSES.map((s) => (
            <option key={s} value={s}>{s || "any status"}</option>
          ))}
        </select>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>{s || "any severity"}</option>
          ))}
        </select>
      </div>
      {isLoading && <p>Loading…</p>}
      {error && <p className="error">Could not load findings.</p>}
      {data && (
        <table>
          {/* Ordered by priority (ADR-069): KEV, then exposure, criticality,
              EPSS/CVSS, severity. A KEV-listed CVE outranks a higher-CVSS one
              that is not — the finding list's first meaningful order. */}
          <caption className="table-caption">Ordered by priority — KEV-listed first, not by severity.</caption>
          <thead>
            <tr>
              <th>Priority</th><th>Severity</th><th>Rule</th><th>Asset</th><th>Where</th>
              <th>Confidence</th><th className="num">EPSS</th><th className="num">Zones</th><th>Status</th>
            </tr>
          </thead>
          <tbody>
            {data.findings.map((f) => (
              <tr key={f.id} className={`frow frow-${f.severity}`}>
                <td><PriorityCell f={f} /></td>
                <td><span className={`sev sev-${f.severity}`}>{f.severity}</span></td>
                <td><Link to={`/findings/${f.id}`}>{f.rule}</Link></td>
                <td className="data">{f.asset_hostname || f.asset_id}</td>
                <td className="data">{f.instance_locator || "—"}</td>
                <td><Confidence value={f.confidence} /></td>
                <td className="num">{epssText(f.epss)}</td>
                <td className="num muted">{f.exposure_zones}</td>
                <td className="muted">{f.status}</td>
              </tr>
            ))}
            {data.findings.length === 0 && (
              <tr className="empty"><td colSpan={9}>No findings match these filters.</td></tr>
            )}
          </tbody>
        </table>
      )}
    </section>
  );
}
