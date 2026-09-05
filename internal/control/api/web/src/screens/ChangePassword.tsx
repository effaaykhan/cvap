import { useState, type FormEvent } from "react";
import { api, ApiError } from "../lib/api";
import { useAuth } from "../lib/auth";

export function ChangePassword() {
  const { refresh, setMustChange } = useAuth();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      await api.changePassword(current, next);
      setMustChange(false);
      await refresh();
    } catch (x) {
      setErr(x instanceof ApiError ? x.message : "Could not change the password.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="center">
      <form className="card login" onSubmit={submit}>
        <h1>Change your password</h1>
        <p className="muted">This account must set a new password before continuing.</p>
        <label>
          Current password
          <input type="password" value={current} onChange={(e) => setCurrent(e.target.value)} />
        </label>
        <label>
          New password
          <input type="password" value={next} onChange={(e) => setNext(e.target.value)} />
        </label>
        {err && <p className="error">{err}</p>}
        <button type="submit" disabled={busy}>
          {busy ? "Saving…" : "Change password"}
        </button>
      </form>
    </div>
  );
}
