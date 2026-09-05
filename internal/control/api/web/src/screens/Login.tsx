import { useState, type FormEvent } from "react";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";

export function Login() {
  const { refresh, setMustChange } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      const r = await api.login(email, password);
      if (r.must_change_password) {
        setMustChange(true); // App routes to ChangePassword
        return;
      }
      await refresh();
    } catch {
      // The server returns one refusal for every failure — wrong password,
      // unknown address, another tenant's address — so the UI shows one message.
      setErr("Sign in failed. Check your email and password.");
    } finally {
      setBusy(false);
    }
  };

  const sso = async () => {
    setErr("");
    try {
      const r = await api.startOIDC(window.location.pathname);
      window.location.href = r.authorization_url;
    } catch {
      setErr("Single sign-on is not available for this tenant.");
    }
  };

  return (
    <div className="center">
      <form className="card login" onSubmit={submit}>
        <h1>CVAP</h1>
        <label>
          Email
          <input value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" />
        </label>
        <label>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
        </label>
        {err && <p className="error">{err}</p>}
        <button type="submit" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
        <button type="button" className="link" onClick={() => void sso()}>
          Sign in with SSO
        </button>
      </form>
    </div>
  );
}
