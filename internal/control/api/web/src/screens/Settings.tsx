import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, has } from "../lib/api";
import { useAuth } from "../lib/auth";

// Settings: self-service account actions for the signed-in operator. Today that
// is changing your own password, through the same POST /v1/auth/password the
// forced first-login flow uses — this is that action made reachable at any time,
// not only when the account is flagged must-change.
export function Settings() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [err, setErr] = useState("");
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setErr("");
    setDone(false);
    if (next !== confirm) {
      setErr("The new password and its confirmation do not match.");
      return;
    }
    if (next.length < 12) {
      setErr("A password must be at least 12 characters.");
      return;
    }
    setBusy(true);
    try {
      await api.changePassword(current, next);
      setDone(true);
      setCurrent("");
      setNext("");
      setConfirm("");
    } catch (x) {
      setErr(x instanceof ApiError ? x.message : "Could not change the password.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="detail">
      <h1>Settings</h1>

      <h2>Change your password</h2>
      <form className="card" onSubmit={submit} style={{ maxWidth: "24rem" }}>
        <label>
          Current password
          <input type="password" autoComplete="current-password" value={current}
            onChange={(e) => setCurrent(e.target.value)} />
        </label>
        <label>
          New password
          <input type="password" autoComplete="new-password" value={next}
            onChange={(e) => setNext(e.target.value)} />
        </label>
        <label>
          Confirm new password
          <input type="password" autoComplete="new-password" value={confirm}
            onChange={(e) => setConfirm(e.target.value)} />
        </label>
        <p className="muted small">At least 12 characters.</p>
        {err && <p className="error">{err}</p>}
        {done && <p className="muted">Password changed. Your current sessions stay signed in.</p>}
        <button type="submit" disabled={busy}>
          {busy ? "Saving…" : "Change password"}
        </button>
      </form>

      <IdentityWindow />
      <CredentialPins />
    </section>
  );
}

// The sighting window as a tenant setting (ADR-100): how long a sighting counts
// toward observed trust and an address is evidence of the same host. Shown with
// its bounds and the measured scan cadence, because a window under twice the
// cadence is one no observed key ever satisfies — the API refuses it.
function IdentityWindow() {
  const { session } = useAuth();
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({ queryKey: ["identity-settings"], queryFn: api.identitySettings });
  const [hours, setHours] = useState<string>("");
  const [reason, setReason] = useState("");
  const [outcome, setOutcome] = useState("");
  const save = useMutation({
    mutationFn: () => api.setIdentityWindow(Number(hours), reason),
    onSuccess: (res) => {
      setOutcome(`Saved: ${res.sighting_window_hours} hours.`);
      setHours("");
      setReason("");
      void qc.invalidateQueries({ queryKey: ["identity-settings"] });
    },
    onError: (e: Error) => setOutcome(e.message),
  });
  if (isLoading || !data) return <><h2>Identity window</h2><p className="muted">Loading…</p></>;
  return (
    <>
      <h2>Identity window</h2>
      <div className="card" style={{ maxWidth: "36rem" }}>
        <p>
          <b>{data.sighting_window_hours} hours</b>{data.is_default ? " (the default)" : ""} — a key CVAP observed becomes credentialed trust material once
          two scans have seen it at the address inside this window (ADR-094), and an address stays evidence of the same host for as long.
        </p>
        <p className="small muted">
          Bounds {data.min_hours}–{data.max_hours} hours.{" "}
          {data.scan_cadence_hours != null
            ? <>Measured scan cadence: <b>{data.scan_cadence_hours.toFixed(1)} hours</b> (median over {data.scan_cadence_samples} completed scans); a window under twice that is refused.</>
            : <>Scan cadence not yet measurable (fewer than two completed scans).</>}
        </p>
        {/* The rule is checked at the write; the card checks it every time it
            renders, so a tenant on the default that has slowed its scanning
            sees the consequence without editing anything (ADR-100). */}
        {data.scan_cadence_hours != null && data.sighting_window_hours < 2 * data.scan_cadence_hours && (
          <p className="error small">
            The current window ({data.sighting_window_hours} hours) is under twice the measured cadence ({(2 * data.scan_cadence_hours).toFixed(1)} hours):
            no observed key can be seen by two scans inside it, so the credentialed path trusts nothing observed. Scan more often, or widen the window.
          </p>
        )}
        {has(session, "policy.write") ? (
          <div className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
            <input type="number" min={data.min_hours} max={data.max_hours} placeholder="hours" value={hours} onChange={(e) => setHours(e.target.value)} style={{ width: 100 }} />
            <input placeholder="Why (recorded with your name)" value={reason} onChange={(e) => setReason(e.target.value)} style={{ minWidth: 260 }} />
            <button className="btn small-btn" disabled={save.isPending || !hours || !reason} onClick={() => save.mutate()}>Set the window</button>
            {outcome && <span className="small">{outcome}</span>}
          </div>
        ) : <p className="faint small">Changing it needs the policy.write permission.</p>}
      </div>
    </>
  );
}

// Operator pins on credential profiles (ADR-091 §4, ADR-100): the one trust
// root chosen by a person, outranking whatever discovery observed for the hosts
// it names. Plain known_hosts lines; pinning or clearing is a trust decision,
// recorded with the operator and the fingerprints.
function CredentialPins() {
  const { session } = useAuth();
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({ queryKey: ["credential-profiles"], queryFn: api.listCredentialProfiles });
  const [lines, setLines] = useState<Record<string, string>>({});
  const [reason, setReason] = useState<Record<string, string>>({});
  const [outcome, setOutcome] = useState<Record<string, string>>({});
  const pin = useMutation({
    mutationFn: (v: { id: string }) => api.pinKnownHosts(v.id, lines[v.id] ?? "", reason[v.id] ?? ""),
    onSuccess: (res, v) => {
      setOutcome((o) => ({ ...o, [v.id]: `Pinned ${res.lines} line${res.lines === 1 ? "" : "s"}: ${res.fingerprints.join(", ")}` }));
      setLines((l) => ({ ...l, [v.id]: "" }));
      void qc.invalidateQueries({ queryKey: ["credential-profiles"] });
    },
    onError: (e: Error, v) => setOutcome((o) => ({ ...o, [v.id]: e.message })),
  });
  const clear = useMutation({
    mutationFn: (v: { id: string }) => api.clearPin(v.id, reason[v.id] ?? ""),
    onSuccess: (_res, v) => {
      setOutcome((o) => ({ ...o, [v.id]: "Pin cleared; the observed key is used again." }));
      void qc.invalidateQueries({ queryKey: ["credential-profiles"] });
    },
    onError: (e: Error, v) => setOutcome((o) => ({ ...o, [v.id]: e.message })),
  });
  if (!has(session, "policy.read")) return null;
  const profiles = data?.profiles ?? [];
  return (
    <>
      <h2>Credential profile pins</h2>
      {isLoading ? <p className="muted">Loading…</p> : profiles.length === 0 ? (
        <p className="muted">No credential profiles. A profile is created with its secret pointer at provisioning; this screen only pins host keys on one.</p>
      ) : profiles.map((p) => (
        <div className="card" key={p.id} style={{ marginBottom: 12, maxWidth: "48rem" }}>
          <p><b className="data">{p.name}</b> <span className="faint small">{p.cred_type}{p.username ? ` · user ${p.username}` : ""}</span>
            {" "}<span className={`chip ${p.pin_lines > 0 ? "chip-ok" : "chip-muted"}`}>{p.pin_lines > 0 ? `${p.pin_lines} pinned line${p.pin_lines === 1 ? "" : "s"}` : "observed key"}</span></p>
          <p className="small muted">A pinned line outranks the observed key for the host it names. Without a pin, the fleet path trusts a key only after two scans have seen it at the address (ADR-094).</p>
          {has(session, "credential.pin") ? (
            <>
              <textarea rows={3} placeholder={"10.0.0.5 ssh-ed25519 AAAA…\nhost6,10.0.0.6 ssh-ed25519 AAAA…"} value={lines[p.id] ?? ""}
                onChange={(e) => setLines((l) => ({ ...l, [p.id]: e.target.value }))} style={{ width: "100%", fontFamily: "monospace" }} />
              <div className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                <input placeholder="Why (recorded with your name)" value={reason[p.id] ?? ""} onChange={(e) => setReason((r) => ({ ...r, [p.id]: e.target.value }))} style={{ minWidth: 260 }} />
                <button className="btn small-btn" disabled={pin.isPending || !(lines[p.id] ?? "").trim() || !reason[p.id]} onClick={() => pin.mutate({ id: p.id })}>Pin these keys</button>
                {p.pin_lines > 0 && <button className="btn small-btn" disabled={clear.isPending || !reason[p.id]} onClick={() => clear.mutate({ id: p.id })}>Clear the pin</button>}
                {outcome[p.id] && <span className="small">{outcome[p.id]}</span>}
              </div>
              <p className="faint small">A pin verifies nothing (B44): it is your word that these keys are the hosts' own, and it hands the credentialed dial to whoever holds them.</p>
            </>
          ) : <p className="faint small">Pinning needs the credential.pin permission.</p>}
        </div>
      ))}
    </>
  );
}
