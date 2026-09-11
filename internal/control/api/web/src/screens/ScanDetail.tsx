import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, has } from "../lib/api";
import { useAuth } from "../lib/auth";

export function ScanDetail() {
  const { id = "" } = useParams();
  const { session } = useAuth();
  const qc = useQueryClient();
  const { data: s, isLoading, error } = useQuery({
    queryKey: ["scan", id],
    queryFn: () => api.getScan(id),
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
    </section>
  );
}
