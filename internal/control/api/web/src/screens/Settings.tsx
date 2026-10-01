import { useId, useState, type FormEvent, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, has } from "../lib/api";
import { useAuth } from "../lib/auth";
import { PageHead } from "../components/PageHead";

// Settings: the tenant's identity-trust controls and the signed-in operator's
// own account. Two trust cards side by side, the password form full width
// beneath them; every control here is an existing API, only arranged.
export function Settings() {
  return (
    <section className="settings">
      <PageHead title="Settings" sub="Manage security and account preferences." />

      <h2>Identity &amp; trust</h2>
      <div className="settings-grid">
        <IdentityWindow />
        <CredentialPins />
      </div>

      <h2>Account</h2>
      <ChangePasswordCard />
    </section>
  );
}

// Changing your own password, through the same POST /v1/auth/password the
// forced first-login flow uses — this is that action made reachable at any time,
// not only when the account is flagged must-change.
function ChangePasswordCard() {
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
    <form className="card settings-card" onSubmit={submit}>
      <h3>Change Password</h3>
      <p className="settings-sub">Update your CVAP account password.</p>
      <div className="settings-pw-grid">
        <PasswordField label="Current password" autoComplete="current-password" value={current} onChange={setCurrent} />
        <PasswordField label="New password" autoComplete="new-password" value={next} onChange={setNext} />
        <PasswordField label="Retype new password" autoComplete="new-password" value={confirm} onChange={setConfirm} />
      </div>
      <p className="faint small settings-hint">At least 12 characters.</p>
      {err && <p className="error small settings-msg">{err}</p>}
      {done && <p className="muted small settings-msg">Password changed. Your current sessions stay signed in.</p>}
      <div className="settings-actions">
        <button type="submit" disabled={busy}>
          {busy ? "Saving…" : "Change password"}
        </button>
      </div>
    </form>
  );
}

// One password input with its own visibility toggle: each field remembers its
// own state, so revealing the new password never reveals the current one.
function PasswordField({ label, autoComplete, value, onChange }: {
  label: string; autoComplete: string; value: string; onChange: (v: string) => void;
}) {
  const id = useId();
  const [shown, setShown] = useState(false);
  const toggle = shown ? "Hide password" : "Show password";
  return (
    <div className="settings-field">
      <label htmlFor={id}>{label}</label>
      <div className="settings-pw">
        <input id={id} type={shown ? "text" : "password"} autoComplete={autoComplete} value={value}
          onChange={(e) => onChange(e.target.value)} />
        <button type="button" className="settings-pw-toggle" onClick={() => setShown((v) => !v)}
          aria-label={toggle} title={toggle} aria-pressed={shown}>
          {shown ? <EyeOffIcon /> : <EyeIcon />}
        </button>
      </div>
    </div>
  );
}

// The sighting window as a tenant setting (ADR-100): how long a sighting counts
// toward observed trust and an address is evidence of the same host. Shown with
// its bounds and the measured scan cadence, because a window under twice the
// cadence is one no observed key ever satisfies — the API refuses it.
function IdentityWindow() {
  const { session } = useAuth();
  const qc = useQueryClient();
  const hoursId = useId();
  const reasonId = useId();
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
      // The PUT answers with the settings as stored; show them at once, then
      // refetch as before.
      qc.setQueryData(["identity-settings"], res);
      void qc.invalidateQueries({ queryKey: ["identity-settings"] });
    },
    onError: (e: Error) => setOutcome(e.message),
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!save.isPending && hours && reason) save.mutate();
  };

  if (isLoading || !data) {
    return (
      <div className="card settings-card">
        <h3>Identity Window</h3>
        <p className="muted small">Loading…</p>
      </div>
    );
  }
  const cadence = data.scan_cadence_hours;
  // The rule is checked at the write; the card checks it every time it
  // renders, so a tenant on the default that has slowed its scanning sees the
  // consequence without editing anything (ADR-100).
  const tooShort = cadence != null && data.sighting_window_hours < 2 * cadence;
  const days = (h: number) => {
    const d = h / 24;
    return Number.isInteger(d) ? `${d}` : d.toFixed(1);
  };
  return (
    <div className="card settings-card">
      <h3>Identity Window</h3>

      <div className="settings-stat">
        <div className="lbl">Current window</div>
        <div className="settings-value">
          {data.sighting_window_hours} hours
          {data.is_default && <span className="chip chip-muted">default</span>}
        </div>
      </div>
      <p className="muted small settings-explain">
        Two scans must observe the same SSH host identity within this window before CVAP treats it as observed
        trust (ADR-094), and an address stays evidence of the same host for as long.
      </p>

      <div className="settings-stat">
        <div className="lbl">Scan cadence</div>
        {cadence != null ? (
          <>
            <div className="settings-value">{cadence.toFixed(1)} hours</div>
            <div className="faint small">Median over {data.scan_cadence_samples} completed scans</div>
          </>
        ) : (
          <div className="faint small">Not yet measurable (fewer than two completed scans).</div>
        )}
      </div>

      {cadence != null && (tooShort ? (
        <p className="error small settings-msg">
          <span className="chip chip-danger">Incompatible</span>{" "}
          The current window ({data.sighting_window_hours} hours) is under twice the measured cadence ({(2 * cadence).toFixed(1)} hours):
          no observed key can be seen by two scans inside it, so the credentialed path trusts nothing observed. Scan more often, or widen the window.
        </p>
      ) : (
        <p className="settings-msg">
          <span className="chip chip-ok">✓ Compatible</span>{" "}
          <span className="faint small">At least twice the scan cadence; a shorter window is refused.</span>
        </p>
      ))}

      {has(session, "policy.write") ? (
        // noValidate: the bounds are the server's to enforce, and its refusal
        // is the message shown — the browser's own tooltip would pre-empt it.
        <form className="settings-edit" onSubmit={submit} noValidate>
          <label className="lbl" htmlFor={hoursId}>Set new window</label>
          <div className="settings-inline">
            <input id={hoursId} type="number" min={data.min_hours} max={data.max_hours} placeholder="Hours"
              value={hours} onChange={(e) => setHours(e.target.value)} />
            <button type="submit" disabled={save.isPending || !hours || !reason}>Set window</button>
          </div>
          <p className="faint small settings-hint">
            Allowed range: {data.min_hours}–{data.max_hours} hours ({days(data.min_hours)}–{days(data.max_hours)} days).
          </p>
          <div className="settings-field settings-reason">
            <label htmlFor={reasonId}>Reason <span className="faint">· recorded with your name</span></label>
            <input id={reasonId} placeholder="Why are you changing this?" value={reason} onChange={(e) => setReason(e.target.value)} />
          </div>
          {outcome && <p className={`small settings-msg ${save.isError ? "error" : "muted"}`}>{outcome}</p>}
        </form>
      ) : <p className="faint small">Changing it needs the policy.write permission.</p>}
    </div>
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
  let body: ReactNode;
  if (isLoading) {
    body = <p className="muted small">Loading…</p>;
  } else if (profiles.length === 0) {
    body = (
      <div className="settings-empty">
        <p>No credential profiles configured.</p>
        <p className="muted small">
          Profiles are created during provisioning.<br />
          Host-key pins can be managed here when a profile exists.
        </p>
      </div>
    );
  } else {
    body = profiles.map((p) => (
      <div className="settings-profile" key={p.id}>
        <p><b className="data">{p.name}</b> <span className="faint small">{p.cred_type}{p.username ? ` · user ${p.username}` : ""}</span>
          {" "}<span className={`chip ${p.pin_lines > 0 ? "chip-ok" : "chip-muted"}`}>{p.pin_lines > 0 ? `${p.pin_lines} pinned line${p.pin_lines === 1 ? "" : "s"}` : "observed key"}</span></p>
        <p className="small muted">A pinned line outranks the observed key for the host it names. Without a pin, the fleet path trusts a key only after two scans have seen it at the address (ADR-094).</p>
        {has(session, "credential.pin") ? (
          <>
            <textarea rows={3} placeholder={"10.0.0.5 ssh-ed25519 AAAA…\nhost6,10.0.0.6 ssh-ed25519 AAAA…"} value={lines[p.id] ?? ""}
              onChange={(e) => setLines((l) => ({ ...l, [p.id]: e.target.value }))} style={{ width: "100%", fontFamily: "monospace" }} />
            <div className="settings-inline settings-wrap">
              <input placeholder="Why (recorded with your name)" value={reason[p.id] ?? ""} onChange={(e) => setReason((r) => ({ ...r, [p.id]: e.target.value }))} />
              <button disabled={pin.isPending || !(lines[p.id] ?? "").trim() || !reason[p.id]} onClick={() => pin.mutate({ id: p.id })}>Pin these keys</button>
              {p.pin_lines > 0 && <button disabled={clear.isPending || !reason[p.id]} onClick={() => clear.mutate({ id: p.id })}>Clear the pin</button>}
            </div>
            {outcome[p.id] && <p className="small settings-msg">{outcome[p.id]}</p>}
            <p className="faint small">A pin verifies nothing (B44): it is your word that these keys are the hosts' own, and it hands the credentialed dial to whoever holds them.</p>
          </>
        ) : <p className="faint small">Pinning needs the credential.pin permission.</p>}
      </div>
    ));
  }
  return (
    <div className="card settings-card">
      <h3>Credential Profile Pins</h3>
      {body}
    </div>
  );
}

/* ---- icons: the console's outline set, stroke inherits currentColor ----- */
function Icon({ children }: { children: ReactNode }) {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75"
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">
      {children}
    </svg>
  );
}
const EyeIcon = () => (
  <Icon>
    <path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Z" />
    <circle cx="12" cy="12" r="3" />
  </Icon>
);
const EyeOffIcon = () => (
  <Icon>
    <path d="M10.6 5.1A10.7 10.7 0 0 1 12 5c6.4 0 10 7 10 7a17.6 17.6 0 0 1-2.9 3.9" />
    <path d="M6.6 6.6C3.7 8.4 2 12 2 12s3.6 7 10 7a9.9 9.9 0 0 0 5.4-1.6" />
    <path d="M9.9 9.9a3 3 0 0 0 4.2 4.2" />
    <path d="m2 2 20 20" />
  </Icon>
);
