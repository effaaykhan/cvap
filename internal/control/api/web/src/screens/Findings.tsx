import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { ExportButton } from "../components/ExportButton";

const SEVERITIES = ["", "critical", "high", "medium", "low", "info"];
const STATUSES = ["", "open", "confirmed", "false_positive", "accepted_risk", "remediated", "closed"];

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
          <thead>
            <tr><th>Severity</th><th>Rule</th><th>Asset</th><th>Where</th><th>Zones</th><th>Status</th></tr>
          </thead>
          <tbody>
            {data.findings.map((f) => (
              <tr key={f.id}>
                <td><span className={`sev sev-${f.severity}`}>{f.severity}</span></td>
                <td><Link to={`/findings/${f.id}`}>{f.rule}</Link></td>
                <td>{f.asset_hostname || f.asset_id}</td>
                <td>{f.instance_locator}</td>
                <td>{f.exposure_zones}</td>
                <td>{f.status}</td>
              </tr>
            ))}
            {data.findings.length === 0 && (
              <tr><td colSpan={6} className="muted">No findings match.</td></tr>
            )}
          </tbody>
        </table>
      )}
    </section>
  );
}
