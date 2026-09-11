import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "../lib/api";

// The scan list lives on Health (console rung 4); this file keeps the create
// form, which Health renders for an operator holding scan.create.

export function CreateScan() {
  const nav = useNavigate();
  const qc = useQueryClient();
  const policies = useQuery({ queryKey: ["policies"], queryFn: () => api.listPolicies(), retry: false });
  const [policyID, setPolicyID] = useState("");
  const [scanType, setScanType] = useState("discovery");
  const [targetType, setTargetType] = useState("cidr");
  const [targets, setTargets] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

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
        policy_id: policyID,
        scan_type: scanType,
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
    <form className="card create" onSubmit={submit}>
      <h2>New scan</h2>
      <div className="filters">
        {policies.data ? (
          <select value={policyID} onChange={(e) => setPolicyID(e.target.value)}>
            <option value="">choose a policy…</option>
            {policies.data.policies.map((p) => (
              <option key={p.id} value={p.id}>{p.name}</option>
            ))}
          </select>
        ) : (
          <input placeholder="policy id" value={policyID} onChange={(e) => setPolicyID(e.target.value)} />
        )}
        <select value={scanType} onChange={(e) => setScanType(e.target.value)}>
          <option value="discovery">discovery</option>
          <option value="fingerprint">fingerprint</option>
          <option value="host">host (credentialed inventory)</option>
        </select>
        <select value={targetType} onChange={(e) => setTargetType(e.target.value)}>
          <option value="cidr">cidr</option>
          <option value="host">host</option>
          <option value="url">url</option>
        </select>
      </div>
      <textarea
        placeholder="one target per line"
        value={targets}
        onChange={(e) => setTargets(e.target.value)}
        rows={3}
      />
      <label className="check">
        <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
        I attest these targets are authorised for scanning.
      </label>
      {err && <p className="error">{err}</p>}
      <button type="submit" disabled={busy}>{busy ? "Creating…" : "Create scan"}</button>
    </form>
  );
}
