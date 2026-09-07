import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { EvidenceBlock } from "../components/Evidence";
import { Confidence } from "../components/Confidence";

// The finding detail: read the finding, its rule, the evidence that produced it,
// and the zones it is exposed from — and confirm the claim by hand without
// re-scanning (constraint 1, week 6's argument).
export function FindingDetail() {
  const { id = "" } = useParams();
  const { data: f, isLoading, error } = useQuery({
    queryKey: ["finding", id],
    queryFn: () => api.getFinding(id),
  });

  if (isLoading) return <p>Loading…</p>;
  if (error || !f) return <p className="error">Could not load this finding.</p>;

  return (
    <section className="detail">
      <p className="crumb"><Link to="/findings">← Findings</Link></p>
      <div className="row-between">
        <h1><span className={`sev sev-${f.severity}`}>{f.severity}</span> {f.rule}</h1>
        <span className="tag">{f.status}</span>
      </div>
      <dl className="facts">
        <div className="kv"><dt>Asset</dt><dd><Link to={`/assets/${f.asset_id}`}>{f.asset_hostname || f.asset_id}</Link></dd></div>
        <div className="kv"><dt>Where</dt><dd className="data">{f.instance_locator || "—"}</dd></div>
        <div className="kv"><dt>Category</dt><dd>{f.category}</dd></div>
        <div className="kv"><dt>Confidence</dt><dd><Confidence value={f.confidence} /></dd></div>
        {f.cwe && <div className="kv"><dt>CWE</dt><dd>{f.cwe}</dd></div>}
        <div className="kv"><dt>Dedup key</dt><dd><code>{f.dedup_key}</code></dd></div>
        <div className="kv"><dt>First seen</dt><dd>{fmt(f.first_seen)}</dd></div>
        <div className="kv"><dt>Last seen</dt><dd>{fmt(f.last_seen)}</dd></div>
      </dl>

      {f.remediation && (
        <>
          <h2>Remediation</h2>
          <p>{f.remediation}</p>
        </>
      )}

      <h2>Evidence</h2>
      <p className="muted">The values the rule read, so you can confirm this without re-scanning.</p>
      <EvidenceBlock evidence={f.evidence ?? []} />

      <h2>Exposure</h2>
      {f.exposures?.length ? (
        <table>
          <thead><tr><th>Zone</th><th>Type</th><th>Last confirmed</th></tr></thead>
          <tbody>
            {f.exposures.map((e, i) => (
              <tr key={i}>
                <td>{e.zone_name || e.zone_id}</td>
                <td>{e.zone_type}</td>
                <td>{fmt(e.last_confirmed)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="muted">No zone exposure recorded.</p>
      )}
      <p className="note">
        Exposure lists the zones this finding was seen from. It is not an internet-reachability
        assessment — that is not yet computed.
      </p>
    </section>
  );
}

function fmt(t?: string): string {
  return t ? new Date(t).toLocaleString() : "—";
}
