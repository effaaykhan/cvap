import { useState, type FormEvent } from "react";
import { api, ApiError } from "../lib/api";

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
    </section>
  );
}
