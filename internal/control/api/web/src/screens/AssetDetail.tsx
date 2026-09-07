import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";

export function AssetDetail() {
  const { id = "" } = useParams();
  const { data: a, isLoading, error } = useQuery({
    queryKey: ["asset", id],
    queryFn: () => api.getAsset(id),
  });
  if (isLoading) return <p>Loading…</p>;
  if (error || !a) return <p className="error">Could not load this asset.</p>;

  return (
    <section className="detail">
      <p className="crumb"><Link to="/assets">← Assets</Link></p>
      <h1>{a.hostname || a.id}</h1>
      <dl className="facts">
        <div className="kv"><dt>Environment</dt><dd>{a.environment || "—"}</dd></div>
        <div className="kv"><dt>OS</dt><dd>{osCell(a.os_family, a.os_version)}</dd></div>
        <div className="kv"><dt>Criticality</dt><dd>{a.criticality}</dd></div>
        <div className="kv"><dt>Fragile</dt><dd>{a.fragile ? "yes" : "no"}</dd></div>
        <div className="kv"><dt>Open findings</dt><dd>{a.open_findings}</dd></div>
        <div className="kv"><dt>First seen</dt><dd>{fmt(a.first_seen)}</dd></div>
        <div className="kv"><dt>Last seen</dt><dd>{fmt(a.last_seen)}</dd></div>
      </dl>

      <h2>Addresses</h2>
      {a.addresses?.length ? (
        <table><thead><tr><th>IP</th><th>MAC</th><th>Since</th></tr></thead>
          <tbody>{a.addresses.map((ad, i) => (
            <tr key={i}><td className="data">{ad.ip || "—"}</td><td className="data">{ad.mac || "—"}</td><td className="data">{fmt(ad.valid_from)}</td></tr>
          ))}</tbody></table>
      ) : <p className="muted">No current addresses.</p>}

      <h2>Services</h2>
      {a.services?.length ? (
        <>
          <table><thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr></thead>
            <tbody>{a.services.map((s, i) => (
              <tr key={i}>
                <td className="data">{s.port}/{s.protocol}</td>
                <td className="data">{s.service || <span className="unknown">unknown</span>}</td>
                <td className="data">{s.product || <span className="unknown">unknown</span>}</td>
                <td className="data">{s.version || <span className="unknown">unknown</span>}</td>
              </tr>
            ))}</tbody></table>
          <p className="note">
            Services are identified from banners and ports. Where product or version reads
            “unknown”, the service answered but did not reveal one — not a version this scan could
            confirm.
          </p>
        </>
      ) : <p className="muted">No services observed.</p>}
    </section>
  );
}

// osCell renders the OS with its uncertainty attached. OS here is inferred from
// service banners, never confirmed, and the data model carries no OS-confidence
// field — so the value must not read as a hard fact. The "inferred" label is the
// honest presentation the runbook's limitations require, made legible.
function osCell(family?: string, version?: string) {
  const os = [family, version].filter(Boolean).join(" ");
  if (!os) return "—";
  return <>{os} <span className="hint">· inferred from banner, low confidence</span></>;
}

function fmt(t?: string): string { return t ? new Date(t).toLocaleString() : "—"; }
