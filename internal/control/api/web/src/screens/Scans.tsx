import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, has } from "../lib/api";
import { useAuth } from "../lib/auth";
import { PageHead } from "../components/PageHead";
import { SegmentBar, type SegmentSpec } from "../components/Charts";
import { ago, scanReadiness, worstFirst } from "../lib/console";

// Scans: where an operator starts one and sees the ones that ran. The form
// says, before anything is submitted, whether a scan CAN run — the same facts
// Core refuses on (a capable scan point online in a permitted zone, a policy
// with an allow rule) — so "no option to scan" becomes "here is what is
// missing", in words that name the fix.
const ENGINE_FOR: Record<string, string> = { discovery: "discovery", fingerprint: "fingerprint", host: "host" };
const SCAN_DOT: Record<string, string> = { failed: "warn", killed: "danger", cancelled: "muted", running: "accent", planning: "accent", pending: "medium", completed: "ok" };
const SCAN_STATE: Record<string, string> = { failed: "high", killed: "danger" };

export function Scans() {
  const { session } = useAuth();
  const [status, setStatus] = useState("");
  const scanQ = status ? `?status=${status}&limit=100` : "?limit=100";
  const scans = useQuery({ queryKey: ["scans", scanQ], queryFn: () => api.listScans(scanQ) });
  const rows = scans.data?.scans ?? [];
  const mix: SegmentSpec[] = [
    { key: "running", label: "running", value: rows.filter((x) => ["running", "planning"].includes(x.status)).length, tone: "accent" },
    { key: "pending", label: "pending", value: rows.filter((x) => x.status === "pending").length, tone: "medium" },
    { key: "completed", label: "completed", value: rows.filter((x) => x.status === "completed").length, tone: "ok" },
    { key: "failed", label: "failed / killed", value: rows.filter((x) => ["failed", "killed"].includes(x.status)).length, tone: "danger" },
    { key: "cancelled", label: "cancelled", value: rows.filter((x) => x.status === "cancelled").length, tone: "muted" },
  ];

  return (
    <section>
      <PageHead
        title="Scans"
        sub="Start a scan against authorised targets and follow the ones that ran. A scan is refused, not queued, when nothing could run it — a scanner reporting activity while scanning nothing is the worst failure this product has."
      />
      {has(session, "scan.create") ? <NewScan /> : (
        <p className="note">This account cannot start scans (it lacks the scan.create permission). It can read the ones below.</p>
      )}

      <div className="card section" style={{ marginTop: "1.1rem" }}>
        <div className="card-head">
          <span className="lbl">Recent scans</span>
          <select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="scan status">
            <option value="">any status</option>
            {["pending", "planning", "running", "completed", "failed", "cancelled", "killed"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
        {scans.isLoading && <p className="muted">Loading…</p>}
        {scans.error && <p className="error">Could not load scans.</p>}
        {scans.data && rows.length > 0 && <div style={{ margin: ".5rem 0 .8rem" }}><SegmentBar segments={mix} height={8} caption={`${rows.length} most recent`} /></div>}
        {rows.map((s) => (
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
        {scans.data && rows.length === 0 && <p className="empty">No scans yet{status ? ` with status ${status}` : ""}. Start one above.</p>}
      </div>
    </section>
  );
}

// NewScan is the form plus its readiness panel. The readiness facts come from
// the fleet and policy reads; the form submits regardless, because Core's
// refusal is the control and this panel only explains it ahead of time.
export function NewScan() {
  const nav = useNavigate();
  const qc = useQueryClient();
  const policies = useQuery({ queryKey: ["policies"], queryFn: () => api.listPolicies(), retry: false });
  const points = useQuery({ queryKey: ["scan-points"], queryFn: () => api.listScanPoints(), retry: false });
  const zones = useQuery({ queryKey: ["zones"], queryFn: () => api.listZones(), retry: false });
  const [policyID, setPolicyID] = useState("");
  const rules = useQuery({ queryKey: ["scope-rules", policyID], queryFn: () => api.scopeRules(policyID), enabled: !!policyID, retry: false });
  const [scanType, setScanType] = useState("discovery");
  const [targetType, setTargetType] = useState("cidr");
  const [targets, setTargets] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const fleet = worstFirst(points.data?.scan_points ?? []);
  const readiness = scanReadiness(fleet, ENGINE_FOR[scanType] ?? scanType, rules.data?.rules);
  const online = fleet.filter((p) => p.health === "healthy");

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setErr("");
    const values = targets.split("\n").map((t) => t.trim()).filter(Boolean);
    if (!policyID || values.length === 0) {
      setErr("Choose a policy and enter at least one target.");
      return;
    }
    if (!authorized) {
      setErr("You must attest that these targets are authorised for scanning.");
      return;
    }
    setBusy(true);
    try {
      const scan = await api.createScan({
        policy_id: policyID, scan_type: scanType,
        targets: values.map((value) => ({ type: targetType, value, authorization_verified: true })),
      });
      await qc.invalidateQueries({ queryKey: ["scans"] });
      nav(`/scans/${scan.id}`);
    } catch (x) {
      setErr(x instanceof ApiError ? x.message : "Could not create the scan.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="scan-new">
      <form className="card section" onSubmit={submit}>
        <div className="card-head"><span className="lbl">New scan</span><span className="aside">targets must sit inside the policy's allow rules and an authorised range</span></div>
        <div className="scan-form">
          <label>
            Policy
            {policies.data ? (
              <select value={policyID} onChange={(e) => setPolicyID(e.target.value)}>
                <option value="">choose a policy…</option>
                {policies.data.policies.map((p) => <option key={p.id} value={p.id}>{p.name} · {p.safety_mode}</option>)}
              </select>
            ) : (
              <input placeholder="policy id" value={policyID} onChange={(e) => setPolicyID(e.target.value)} />
            )}
          </label>
          <label>
            Scan type
            <select value={scanType} onChange={(e) => setScanType(e.target.value)}>
              <option value="discovery">discovery — hosts and open ports</option>
              <option value="fingerprint">fingerprint — services, banners, host keys</option>
              <option value="host">host — credentialed package inventory (SSH)</option>
            </select>
          </label>
          <label>
            Target type
            <select value={targetType} onChange={(e) => setTargetType(e.target.value)}>
              <option value="cidr">cidr</option>
              <option value="host">host</option>
            </select>
          </label>
          <label className="wide">
            Targets, one per line
            <textarea placeholder={targetType === "cidr" ? "10.10.0.0/24" : "10.10.0.14"} value={targets} onChange={(e) => setTargets(e.target.value)} rows={3} />
          </label>
        </div>
        {policyID && rules.data && (
          <div className="faint small" style={{ marginTop: ".4rem" }}>
            Scope of this policy: {rules.data.rules.length === 0 ? "no rules — every target would be refused" :
              rules.data.rules.map((r) => `${r.effect} ${r.match_value}`).join(" · ")}
          </div>
        )}
        <label className="check">
          <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
          I attest these targets are authorised for scanning.
        </label>
        {err && <p className="error">{err}</p>}
        <button type="submit" disabled={busy}>{busy ? "Creating…" : "Start scan"}</button>
      </form>

      <div className={`card section${readiness.ok ? "" : " attention"}`}>
        <span className={`lbl${readiness.ok ? "" : " warn"}`}>{readiness.ok ? "Ready to run" : "Cannot run yet"}</span>
        <div className="attn">
          {readiness.reasons.map((r) => <div className="item" key={r}><span className="dot dot-warn" /><span>{r}</span></div>)}
          {readiness.ok && <div className="item"><span className="dot dot-ok" /><span>{online.length} scan point{online.length === 1 ? "" : "s"} online with the {ENGINE_FOR[scanType]} engine.</span></div>}
        </div>
        <div className="lbl" style={{ marginTop: ".9rem" }}>Scan points</div>
        {fleet.map((p) => (
          <div className="hrow" key={p.id}>
            <span><span className={`dot dot-${p.health === "healthy" ? "ok" : p.health === "offline" ? "danger" : "warn"}`} /><span className="name">{p.hostname}</span><span className="zone small">{p.capabilities.join(", ") || "no engines"}</span></span>
            <span className={`state ${p.health === "offline" ? "danger" : ""}`}>{p.health}{p.last_heartbeat ? ` · ${ago(p.last_heartbeat)}` : ""}</span>
          </div>
        ))}
        {points.data && fleet.length === 0 && <p className="empty">No scan point is enrolled.</p>}
        {fleet.length > 0 && online.length === 0 && (
          <div className="not-measured">
            Every scan point is offline. Start one on a host that can reach the targets and this Core; it re-enrols with the certificate it already holds. See deploy/INSTALL.md §6 for the container command.
          </div>
        )}
        {zones.data && (
          <>
            <div className="lbl" style={{ marginTop: ".9rem" }}>Zones</div>
            {zones.data.zones.map((z) => (
              <div className="hrow" key={z.id}><span><span className="name">{z.name}</span><span className="zone small">{z.type}</span></span><span className="state">trust {z.trust_level}</span></div>
            ))}
          </>
        )}
      </div>
    </div>
  );
}
