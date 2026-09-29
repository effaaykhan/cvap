import { useState, type FormEvent, type ReactNode } from "react";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";

export function Login() {
  const { refresh, setMustChange } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
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
      setErr("Sign in failed. Check your username and password.");
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
    <div className="login-page">
      <LoginNetwork />
      <div className="login-layout">
        <section className="login-brand">
          <h1 className="login-brand-mark">CVAP</h1>
          <span className="login-brand-accent" aria-hidden="true" />
          <p className="login-product-name">CyberSentinel Vulnerability Assessment Platform</p>
          <p className="login-tagline">
            Continuous visibility across your environment,{" "}
            <br />
            from assets and scans to security findings.
          </p>
          <ul className="login-features">
            <Feature icon={<MonitorIcon />} tone="blue" title="Asset Visibility">
              Discover and understand your environment
            </Feature>
            <Feature icon={<ShieldIcon />} tone="teal" title="Vulnerability Triage">
              Prioritize security findings
            </Feature>
            <Feature icon={<ChartIcon />} tone="violet" title="Fleet Health">
              Monitor your security infrastructure
            </Feature>
          </ul>
        </section>

        <form className="login-card" onSubmit={submit}>
          <h2 className="login-card-title">Sign in</h2>
          <p className="login-card-subtitle">Access your CVAP workspace</p>

          <div className="login-field">
            <label htmlFor="login-email">Username</label>
            <div className="login-input-wrap">
              <span className="login-input-icon"><MailIcon /></span>
              <input
                id="login-email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="username"
                placeholder="Enter your username"
              />
            </div>
          </div>

          <div className="login-field">
            <label htmlFor="login-password">Password</label>
            <div className="login-input-wrap">
              <span className="login-input-icon"><LockIcon /></span>
              <input
                id="login-password"
                type={showPassword ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                placeholder="Enter your password"
              />
              <button
                type="button"
                className="login-password-toggle"
                onClick={() => setShowPassword((v) => !v)}
                aria-label={showPassword ? "Hide password" : "Show password"}
                aria-pressed={showPassword}
              >
                {showPassword ? <EyeOffIcon /> : <EyeIcon />}
              </button>
            </div>
          </div>

          {err && <p className="error login-error">{err}</p>}

          <button type="submit" className="login-submit" disabled={busy}>
            {busy ? "Signing in…" : "Sign in"}
          </button>

          <div className="login-divider"><span>OR</span></div>

          <button type="button" className="login-sso" onClick={() => void sso()}>
            Sign in with SSO
            <ExternalLinkIcon />
          </button>

          <p className="login-footer">Internal security console</p>
        </form>
      </div>
    </div>
  );
}

function Feature({
  icon,
  tone,
  title,
  children,
}: {
  icon: ReactNode;
  tone: "blue" | "teal" | "violet";
  title: string;
  children: ReactNode;
}) {
  return (
    <li className="login-feature">
      <span className={`login-feature-icon login-feature-icon-${tone}`}>{icon}</span>
      <span>
        <span className="login-feature-title">{title}</span>
        <span className="login-feature-desc">{children}</span>
      </span>
    </li>
  );
}

/* ---- decorative network wave --------------------------------------------
   A warped grid: flowing horizontal curves joined by vertical strands at
   fixed x positions, so the mesh bends with the wave instead of crossing
   it. Computed once at module load; deterministic, no randomness. */
const WAVE_W = 1440;
const WAVE_ROWS = 9;
const WAVE_STEP = 24;
const WAVE_COL = 72;

function waveY(x: number, row: number): number {
  const t = row / (WAVE_ROWS - 1);
  const base = 168 + row * 17;
  return (
    base +
    (46 - t * 18) * Math.sin(x * 0.0042 + row * 0.22) +
    (14 - t * 6) * Math.sin(x * 0.011 - row * 0.35 + 1.3)
  );
}

const WAVE = (() => {
  const f = (n: number) => n.toFixed(1);
  const rows: string[] = [];
  for (let r = 0; r < WAVE_ROWS; r++) {
    let d = "";
    for (let x = 0; x <= WAVE_W; x += WAVE_STEP) d += `${x ? "L" : "M"}${x} ${f(waveY(x, r))}`;
    rows.push(d);
  }
  const cols: string[] = [];
  const nodes: { x: number; y: number; r: number }[] = [];
  for (let c = 0, x = 0; x <= WAVE_W; c++, x += WAVE_COL) {
    let d = "";
    for (let r = 0; r < WAVE_ROWS; r++) {
      d += `${r ? "L" : "M"}${x} ${f(waveY(x, r))}`;
      if ((c * 3 + r * 5) % 7 === 0) nodes.push({ x, y: waveY(x, r), r: (c + r) % 3 === 0 ? 2.4 : 1.6 });
    }
    cols.push(d);
  }
  return { rows, cols, nodes };
})();

function LoginNetwork() {
  return (
    <svg
      className="login-network"
      viewBox={`0 0 ${WAVE_W} 340`}
      preserveAspectRatio="xMidYMax slice"
      aria-hidden="true"
      focusable="false"
    >
      <defs>
        <linearGradient id="login-net-fade" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#fff" stopOpacity="0" />
          <stop offset=".45" stopColor="#fff" stopOpacity=".75" />
          <stop offset="1" stopColor="#fff" stopOpacity="1" />
        </linearGradient>
        <linearGradient id="login-net-edge" x1="0" y1="0" x2="1" y2="0">
          <stop offset="0" stopColor="#fff" stopOpacity=".35" />
          <stop offset=".5" stopColor="#fff" stopOpacity="1" />
          <stop offset="1" stopColor="#fff" stopOpacity=".35" />
        </linearGradient>
        <mask id="login-net-mask">
          <rect width={WAVE_W} height="340" fill="url(#login-net-fade)" />
        </mask>
        <mask id="login-net-mask-x">
          <rect width={WAVE_W} height="340" fill="url(#login-net-edge)" />
        </mask>
        <filter id="login-net-glow" x="-50%" y="-50%" width="200%" height="200%">
          <feGaussianBlur stdDeviation="2.2" />
        </filter>
      </defs>
      <g mask="url(#login-net-mask-x)">
        <g mask="url(#login-net-mask)">
          <g fill="none" stroke="#3EA6F5" strokeWidth="1" strokeLinejoin="round">
            <g opacity=".22">
              {WAVE.rows.map((d, i) => <path key={i} d={d} />)}
            </g>
            <g opacity=".1">
              {WAVE.cols.map((d, i) => <path key={i} d={d} />)}
            </g>
          </g>
          <g fill="#55B3FF">
            <g opacity=".35" filter="url(#login-net-glow)">
              {WAVE.nodes.map((n, i) => <circle key={i} cx={n.x} cy={n.y} r={n.r * 2} />)}
            </g>
            <g opacity=".7">
              {WAVE.nodes.map((n, i) => <circle key={i} cx={n.x} cy={n.y} r={n.r} />)}
            </g>
          </g>
        </g>
      </g>
    </svg>
  );
}

/* ---- icons: inline, decorative, stroke inherits currentColor ------------ */
function Icon({ children, size = 17 }: { children: ReactNode; size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {children}
    </svg>
  );
}

const MailIcon = () => (
  <Icon size={15}>
    <rect x="3" y="5" width="18" height="14" rx="2" />
    <path d="m3.5 6.5 8.5 6 8.5-6" />
  </Icon>
);
const LockIcon = () => (
  <Icon size={15}>
    <rect x="4.5" y="10.5" width="15" height="10" rx="2" />
    <path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" />
  </Icon>
);
const EyeIcon = () => (
  <Icon size={15}>
    <path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12Z" />
    <circle cx="12" cy="12" r="3" />
  </Icon>
);
const EyeOffIcon = () => (
  <Icon size={15}>
    <path d="M10.6 5.1A10.7 10.7 0 0 1 12 5c6.4 0 10 7 10 7a17.6 17.6 0 0 1-2.9 3.9" />
    <path d="M6.6 6.6C3.7 8.4 2 12 2 12s3.6 7 10 7a9.9 9.9 0 0 0 5.4-1.6" />
    <path d="M9.9 9.9a3 3 0 0 0 4.2 4.2" />
    <path d="m2 2 20 20" />
  </Icon>
);
const MonitorIcon = () => (
  <Icon>
    <rect x="2.5" y="3.5" width="19" height="13" rx="2" />
    <path d="M8 20.5h8M12 16.5v4" />
  </Icon>
);
const ShieldIcon = () => (
  <Icon>
    <path d="M12 2.8 4.5 5.6v5.9c0 4.6 3.2 8.3 7.5 9.7 4.3-1.4 7.5-5.1 7.5-9.7V5.6Z" />
    <path d="m9 12 2.2 2.2L15.5 10" />
  </Icon>
);
const ChartIcon = () => (
  <Icon>
    <path d="M3.5 20.5h17" />
    <path d="M7 16.5v-5M12 16.5v-9M17 16.5v-7" />
  </Icon>
);
const ExternalLinkIcon = () => (
  <Icon size={14}>
    <path d="M14 4h6v6" />
    <path d="M20 4 11 13" />
    <path d="M18 14v4.5a1.5 1.5 0 0 1-1.5 1.5h-11A1.5 1.5 0 0 1 4 18.5v-11A1.5 1.5 0 0 1 5.5 6H10" />
  </Icon>
);
