import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, has } from "../lib/api";
import { groupPorts } from "../lib/console";
import { useAuth } from "../lib/auth";

export function ScanDetail() {
  const { id = "" } = useParams();
  const { session } = useAuth();
  const qc = useQueryClient();
  const { data: s, isLoading, error } = useQuery({
    queryKey: ["scan", id],
    queryFn: () => api.getScan(id),
  });
  // What this run actually found. Scan-scoped, so it is read from the scan's
  // own observations rather than from assets (ADR-103 decision 3) — and it
  // therefore empties as those age out, which the panel says rather than
  // leaving an operator to read retention as data loss.
  const { data: results } = useQuery({
    queryKey: ["scan-results", id],
    queryFn: () => api.scanResults(id),
    // A running scan is still producing them.
    refetchInterval: s && ["pending", "planning", "running"].includes(s.status) ? 10000 : false,
  });
  const [msg, setMsg] = useState("");

  if (isLoading) return <p>Loading…</p>;
  if (error || !s) return <p className="error">Could not load this scan.</p>;

  const active = ["pending", "planning", "running"].includes(s.status);
  const cancel = async () => {
    setMsg("");
    try {
      await api.cancelScan(id, "cancelled from the operator UI");
      await qc.invalidateQueries({ queryKey: ["scan", id] });
    } catch (x) {
      // Honest degradation: if the server refuses (403 without scan.cancel, or a
      // scan that already finished), show why rather than a silent no-op.
      setMsg(x instanceof ApiError ? x.message : "Cancel failed.");
    }
  };

  return (
    <section className="detail">
      <p className="crumb"><Link to="/health">← Health</Link></p>
      <h1>Scan {s.id.slice(0, 8)}</h1>
      <dl className="facts">
        <div className="kv"><dt>Type</dt><dd>{s.scan_type}</dd></div>
        <div className="kv"><dt>Status</dt><dd>{s.status}</dd></div>
        <div className="kv"><dt>Created</dt><dd>{s.created_at ? new Date(s.created_at).toLocaleString() : "—"}</dd></div>
      </dl>
      {active && has(session, "scan.cancel") && (
        <button onClick={() => void cancel()}>Cancel scan</button>
      )}
      {msg && <p className="error">{msg}</p>}

      <h2>Open ports found</h2>
      {!results ? (
        <p className="muted">Loading results…</p>
      ) : results.ports.length === 0 ? (
        <p className="muted">
          {active
            ? "Nothing yet. A discovery scan reports a port when it answers, so this fills in as the scan runs."
            : "This scan recorded no open ports. For an older scan that may mean its observations have aged out rather than that it found nothing — what it taught each asset stays on the asset."}
        </p>
      ) : (
        <>
          <p className="muted">
            {results.hosts} host{results.hosts === 1 ? "" : "s"}, {results.ports.length} open port
            {results.ports.length === 1 ? "" : "s"}
            {results.truncated && <> — showing the first {results.limit}</>}.
          </p>
          <table>
            <thead><tr><th>Host</th><th>Open ports</th></tr></thead>
            <tbody>
              {groupPorts(results.ports, (p) => p.address).map(([address, ports]) => (
                <tr key={address}>
                  <td className="data">{address}</td>
                  <td className="data">{ports.map((p) => `${p.port}/${p.protocol}`).join(", ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="muted">
            Read from this scan's observations, which are pruned over time
            (ADR-016) — an older scan shows fewer here, and eventually none.
            What it established about each host persists on the asset.
          </p>
        </>
      )}
    </section>
  );
}
