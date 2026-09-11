import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";
import { ExportButton } from "../components/ExportButton";
import { PageHead } from "../components/PageHead";

export function Assets() {
  const [q, setQ] = useState("");
  const [environment, setEnvironment] = useState("");
  const [fragile, setFragile] = useState("");

  const qs = new URLSearchParams();
  if (q) qs.set("q", q);
  if (environment) qs.set("environment", environment);
  if (fragile) qs.set("fragile", fragile);
  const query = qs.toString() ? `?${qs}` : "";

  const { data, isLoading, error } = useQuery({
    queryKey: ["assets", query],
    queryFn: () => api.listAssets(query),
  });

  return (
    <section>
      <PageHead
        title="Assets"
        sub="What discovery has seen and correlated. Advisory status, OS attribution and its provenance are on each asset."
        action={<ExportButton perm="asset.export_all" href={api.exportURL("assets", query)} />}
      />
      <div className="filters">
        <input placeholder="search hostname or address" value={q} onChange={(e) => setQ(e.target.value)} />
        <input placeholder="environment" value={environment} onChange={(e) => setEnvironment(e.target.value)} />
        <select value={fragile} onChange={(e) => setFragile(e.target.value)}>
          <option value="">fragile: any</option>
          <option value="true">fragile only</option>
          <option value="false">not fragile</option>
        </select>
      </div>
      {isLoading && <p>Loading…</p>}
      {error && <p className="error">Could not load assets.</p>}
      {data && (
        <table>
          <thead><tr><th>Hostname</th><th>OS</th><th>Environment</th><th>Fragile</th><th>Last seen</th></tr></thead>
          <tbody>
            {data.assets.map((a) => (
              <tr key={a.id}>
                <td><Link to={`/assets/${a.id}`}>{a.hostname || a.id}</Link></td>
                <td>{a.os_family || <span className="unknown">unknown</span>}</td>
                <td>{a.environment || "—"}</td>
                <td>{a.fragile ? <span className="chip chip-high">fragile</span> : ""}</td>
                <td className="data">{fmt(a.last_seen)}</td>
              </tr>
            ))}
            {data.assets.length === 0 && <tr><td colSpan={5} className="muted">No assets match.</td></tr>}
          </tbody>
        </table>
      )}
    </section>
  );
}
function fmt(t?: string): string { return t ? new Date(t).toLocaleString() : "—"; }
