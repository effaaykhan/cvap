import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, has } from "../lib/api";
import { useAuth } from "../lib/auth";
import { PageHead } from "../components/PageHead";
import { CreateScan } from "./Scans";
import { ago, fmtTime, threshold, worstFirst } from "../lib/console";

// Fleet & scan health (console rung 4): what is not working, made visible.
// Every state here is the server's own word — scan-point health from
// handlers_ops, scan status from the store, feed freshness against each feed's
// threshold. The pipeline-and-safety reads the spec asks for (ingest backlog,
// kill-switch state, blocked-for-capacity) do not exist yet and are named as
// such rather than approximated.
const SP_DOT: Record<string, string> = { offline: "danger", degraded: "warn", pending: "muted", revoked: "muted", disabled: "muted", healthy: "ok" };
const SP_STATE: Record<string, string> = { offline: "danger", degraded: "warn" };
const SCAN_DOT: Record<string, string> = { failed: "warn", killed: "danger", cancelled: "muted", running: "accent", planning: "accent", pending: "medium", completed: "ok" };
const SCAN_STATE: Record<string, string> = { failed: "high", killed: "danger" };
const ACTIVE = ["pending", "planning", "running", "failed", "killed", "cancelled", "completed"];

export function Health() {
  const { session } = useAuth();
  const [scanStatus, setScanStatus] = useState("");
  const points = useQuery({ queryKey: ["scan-points"], queryFn: () => api.listScanPoints() });
  const scanQ = scanStatus ? `?status=${scanStatus}&limit=50` : "?limit=50";
  const scans = useQuery({ queryKey: ["scans", scanQ], queryFn: () => api.listScans(scanQ) });
  const feeds = useQuery({ queryKey: ["knowledge-freshness"], queryFn: () => api.knowledgeFreshness(), enabled: has(session, "finding.read") });

  const sorted = worstFirst(points.data?.scan_points ?? []);

  return (
    <section>
      <PageHead
        title="Fleet & scan health"
        sub="What is not working, made visible. A dead scan point or a scan that never ran is a silent-success class if you have to hunt for it."
      />
      <div className="health-grid">
        <div className="card section">
          <div className="lbl">Scan points — worst first</div>
          {points.isLoading && <p className="muted">Loading…</p>}
          {points.error && <p className="error">Could not load scan points.</p>}
          {sorted.map((p) => (
            <div className="hrow" key={p.id}>
              <span>
                <span className={`dot dot-${SP_DOT[p.health] ?? "muted"}`} />
                <span className="name">{p.hostname}</span>
                <span className="zone small">zone {p.zone_id.slice(0, 8)} · {p.capabilities.join(", ") || "no engines"}</span>
                {p.health_reason && <span className="reason">{p.health_reason}</span>}
              </span>
              <span className={`state ${SP_STATE[p.health] ?? ""}`}>
                {p.health}{p.last_heartbeat ? ` · ${ago(p.last_heartbeat)}` : ""}
                {p.leases_held > 0 && <span className="reason">{p.leases_held} lease{p.leases_held === 1 ? "" : "s"} held</span>}
              </span>
            </div>
          ))}
          {points.data && sorted.length === 0 && <p className="empty">No scan points enrolled. Enrol one to give a zone a vantage point.</p>}
        </div>

        <div className="card section">
          <div className="card-head">
            <span className="lbl">Scans — recent</span>
            <select value={scanStatus} onChange={(e) => setScanStatus(e.target.value)} aria-label="scan status">
              <option value="">any status</option>
              {ACTIVE.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>
          {scans.isLoading && <p className="muted">Loading…</p>}
          {scans.error && <p className="error">Could not load scans.</p>}
          {(scans.data?.scans ?? []).map((s) => (
            <div className="hrow" key={s.id}>
              <span>
                <span className={`dot dot-${SCAN_DOT[s.status] ?? "muted"}`} />
                <Link className="name" to={`/scans/${s.id}`}>{s.id.slice(0, 8)}</Link>
                <span className="zone small">{s.scan_type} · {s.safety_mode}</span>
              </span>
              <span className={`state ${SCAN_STATE[s.status] ?? ""}`}>
                {s.status}
                <span className="reason">{s.completed_at ? `finished ${ago(s.completed_at)}` : s.started_at ? `started ${ago(s.started_at)}` : `created ${ago(s.created_at)}`}</span>
              </span>
            </div>
          ))}
          {scans.data && scans.data.scans.length === 0 && <p className="empty">No scans{scanStatus ? ` with status ${scanStatus}` : ""}.</p>}
          <div className="not-measured">
            Not read yet: a scan waiting because no scan point covers its zone is indistinguishable here from one that is merely queued. The blocked-for-capacity signal is a planned read.
          </div>
          {has(session, "scan.create") && <CreateScan />}
        </div>

        <div className="card section">
          <div className="card-head">
            <span className="lbl">Knowledge feeds</span>
            <span className="aside"><Link to="/knowledge">coverage & thresholds →</Link></span>
          </div>
          {feeds.isLoading && <p className="muted">Loading…</p>}
          {feeds.error && <p className="error">Could not load feed freshness.</p>}
          {(feeds.data?.feeds ?? []).map((f) => (
            <div className="hrow" key={f.feed}>
              <span>{f.feed} <span className="faint small">({threshold(f.staleness_threshold_seconds)} threshold)</span></span>
              <span className={`chip chip-${f.state === "current" ? "ok" : f.state === "stale" ? "warn" : "muted"}`}>
                {f.state}{f.last_fetched_at ? ` · ${ago(f.last_fetched_at)}` : ""}
              </span>
            </div>
          ))}
          {feeds.data && feeds.data.feeds.length === 0 && <p className="empty">No advisory feeds ingested yet.</p>}
        </div>

        <div className="card section">
          <div className="lbl">Pipeline & safety</div>
          <div className="hrow"><span>Scope enforcement</span><span className="chip chip-ok">2 sites · by construction</span></div>
          <div className="hrow"><span>Ingest backlog <span className="faint small">pending &gt; 1h</span></span><span className="chip chip-muted">no read yet</span></div>
          <div className="hrow"><span>Kill-switch state</span><span className="chip chip-muted">no read yet</span></div>
          <div className="hrow"><span>Unresolved correlations</span><span className="chip chip-muted">no read yet</span></div>
          <div className="not-measured">
            Scope enforcement is a property of the design (Core at planning, the scan point on the send path — ADR-024) and is asserted by the safety gate, not measured live here. The three rows above are counters Core holds and does not yet serve.
          </div>
        </div>
      </div>
      <p className="faint small" style={{ marginTop: "1rem" }}>
        Scan-point health is synthesised by the server from heartbeat age, protocol support and enabled engines; last seen {fmtTime(points.dataUpdatedAt ? new Date(points.dataUpdatedAt).toISOString() : undefined)}.
      </p>
    </section>
  );
}
