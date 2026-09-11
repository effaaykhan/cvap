import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, has, type ChangedFinding } from "../lib/api";
import { useAuth } from "../lib/auth";
import { PageHead } from "../components/PageHead";
import { Trend } from "../components/Trend";
import { ago, attention, kevInversion, score } from "../lib/console";

// The operator landing (console rung 2): what is worst right now, what changed,
// what is not working, and the trend (rung 5). Every number is served by Core
// from the same rows the lists page over — the summary read counts exactly,
// the change window is a fixed number of days, and the series is derived from
// first_seen and resolved_at — so nothing here has a life of its own.
const WINDOW = 7;
const TREND = 30;

export function Overview() {
  const { session } = useAuth();
  const canFindings = has(session, "finding.read");
  const canScans = has(session, "scan.read");

  const stats = useQuery({
    queryKey: ["finding-summary", WINDOW, TREND],
    queryFn: () => api.findingSummary(`?days=${WINDOW}&trend_days=${TREND}`),
    enabled: canFindings,
  });
  const worstQ = useQuery({
    queryKey: ["findings", "?status=open&limit=5"],
    queryFn: () => api.listFindings("?status=open&limit=5"),
    enabled: canFindings,
  });
  const points = useQuery({ queryKey: ["scan-points"], queryFn: () => api.listScanPoints(), enabled: canScans });
  const health = useQuery({ queryKey: ["health"], queryFn: () => api.health(), enabled: canScans });
  const feeds = useQuery({ queryKey: ["knowledge-freshness"], queryFn: () => api.knowledgeFreshness(), enabled: canFindings });
  const scans = useQuery({ queryKey: ["scans", "?limit=50"], queryFn: () => api.listScans("?limit=50"), enabled: canScans });

  const s = stats.data;
  const worst = worstQ.data?.findings ?? [];
  const issues = attention(points.data?.scan_points ?? [], feeds.data?.feeds ?? [], scans.data?.scans ?? [], health.data);
  const healthy = points.data ? points.data.scan_points.filter((p) => p.health === "healthy").length : null;
  const anyLoaded = !!(points.data || feeds.data || health.data);

  return (
    <section>
      <PageHead
        title="Operator overview"
        sub={`Exact counts from the finding set; changes over the last ${WINDOW} days; the series from each finding's first-seen and resolved dates.`}
        meta={<>as of {new Date().toISOString().slice(0, 16).replace("T", " ")}Z</>}
      />

      <div className="metric-strip">
        <div className="card metric">
          <div className="lbl">KEV on fleet</div>
          <div className="row">
            <span className={`value${s && s.kev_open > 0 ? " danger" : ""}`}>{s ? s.kev_open : "—"}</span>
            {s && s.kev_listed_since > 0 && <span className="delta delta-up">▲ {s.kev_listed_since} listed ({WINDOW}d)</span>}
          </div>
          <div className="foot">known-exploited, open · exact</div>
        </div>
        <div className="card metric">
          <div className="lbl">Open findings</div>
          <div className="row">
            <span className="value">{s ? s.open : "—"}</span>
            {s && (
              <span className="delta">
                {s.new_since > 0 && <span className="delta-up">▲ {s.new_since}</span>}
                {s.new_since > 0 && s.resolved_since > 0 && " "}
                {s.resolved_since > 0 && <span className="delta-down">▼ {s.resolved_since}</span>}
                {s.new_since === 0 && s.resolved_since === 0 && <span className="faint">no change ({WINDOW}d)</span>}
              </span>
            )}
          </div>
          <div className="foot">
            {s ? ["critical", "high", "medium", "low", "info"].filter((k) => s.by_severity[k]).map((k) => `${s.by_severity[k]} ${k}`).join(" · ") || "none open" : "ordered by priority, not severity"}
          </div>
        </div>
        <div className="card metric">
          <div className="lbl">Scan points</div>
          <div className="row">
            <span className="value">{healthy ?? "—"}</span>
            <span className="qual">{points.data ? `of ${points.data.scan_points.length} healthy` : ""}</span>
          </div>
          <div className="foot">{health.data?.blocked_scans.length ? `${health.data.blocked_scans.length} scan${health.data.blocked_scans.length === 1 ? "" : "s"} blocked for capacity` : "server-synthesised health"}</div>
        </div>
        <div className={`card metric${issues.length ? " attention" : ""}`}>
          <div className={`lbl${issues.length ? " warn" : ""}`}>Not working</div>
          <div className="row">
            <span className={`value${issues.length ? " warn" : ""}`}>{anyLoaded ? issues.length : "—"}</span>
            <span className="qual">{issues.length === 1 ? "issue" : "issues"}</span>
          </div>
          <div className="foot">kill switch, blocked scans, backlog, scan points, feeds</div>
        </div>
      </div>

      <div className="overview">
        <div className="card section">
          <div className="card-head">
            <span className="lbl">Worst right now</span>
            <span className="aside">priority order · <Link to="/triage">open triage →</Link></span>
          </div>
          {worstQ.isLoading && <p className="muted">Loading…</p>}
          {worstQ.error && <p className="error">Could not load findings.</p>}
          {!canFindings && <p className="muted">This account cannot read findings.</p>}
          {worstQ.data && (
            <div className="worst">
              {worst.map((f) => (
                <div className="frow-line" key={f.id}>
                  <span className={`rail rail-${f.severity}`} />
                  <div>
                    <div className="line1">
                      {f.kev && <span className={`kev-badge${f.kev_ransomware ? " kev-ransomware" : ""}`}>KEV</span>}
                      <Link to={`/findings/${f.id}`}>{f.rule}</Link>
                      <span className="muted small">{f.category}</span>
                    </div>
                    <div className="line2">
                      {f.asset_hostname || f.asset_id}
                      {f.instance_locator ? ` · ${f.instance_locator}` : ""} · EPSS {score(f.epss, 5)}
                      {f.kev ? "" : " · not in KEV"}
                    </div>
                  </div>
                  <div className="right">
                    <span className={`sev sev-${f.severity}`}>{f.severity}</span>
                    <div className="faint">CVSS {score(f.cvss, 1)}</div>
                  </div>
                </div>
              ))}
              {worst.length === 0 && <p className="empty">No open findings. That is a real verdict only where feeds are current and releases are in coverage — see Knowledge.</p>}
            </div>
          )}
          {kevInversion(worst) && (
            <div className="foot-note">
              A KEV-listed finding above outranks a higher-CVSS one below it. Priority, not severity; that inversion is the point.
            </div>
          )}

          <div className="lbl" style={{ marginTop: "1.25rem" }}>Open findings — {TREND} days</div>
          {stats.isLoading && <p className="muted">Loading…</p>}
          {stats.error && <p className="error">Could not load the summary.</p>}
          {s && <Trend points={s.trend} days={s.trend_days} />}
        </div>

        <div className="stack">
          <div className="card section">
            <div className="card-head">
              <span className="lbl">Changed in the last {WINDOW} days</span>
              {s && <span className="aside">{s.new_since} new · {s.resolved_since} resolved · {s.reopened_since} reopened</span>}
            </div>
            {s && (
              <div className="changed">
                {s.kev_listed_items.map((f) => <Changed key={"k" + f.id} f={f} dot="danger" note="newly listed in KEV — re-ranked" />)}
                {s.new_items.filter((n) => !s.kev_listed_items.some((k) => k.id === n.id)).map((f) => <Changed key={f.id} f={f} dot={f.severity === "critical" || f.severity === "high" ? "warn" : "medium"} note="new" />)}
                {s.resolved_since > 0 && (
                  <div className="item"><span className="dot dot-ok" /><span>{s.resolved_since} finding{s.resolved_since === 1 ? "" : "s"} resolved <span className="detail faint">— remediated or superseded by a credentialed read</span></span></div>
                )}
                {s.new_since === 0 && s.resolved_since === 0 && s.reopened_since === 0 && s.kev_listed_since === 0 && (
                  <div className="item"><span className="dot dot-muted" /><span className="muted">Nothing changed in the window.</span></div>
                )}
              </div>
            )}
            <div className="foot-note">A fixed window, not your last visit: the same list for everyone who opens it.</div>
          </div>

          <div className={`card section${issues.length ? " attention" : ""}`}>
            <span className={`lbl${issues.length ? " warn" : ""}`}>Not working{issues.length ? " — attention" : ""}</span>
            {(points.error || feeds.error || health.error) && <p className="error">Could not load fleet, feed or pipeline state.</p>}
            <div className="attn">
              {issues.map((a, i) => (
                <div className="item" key={i}>
                  <span className={`dot dot-${a.level}`} />
                  <span>
                    <Link to={a.to}>{a.text}</Link>
                    {a.detail && <span className="detail"> — {a.detail}</span>}
                  </span>
                </div>
              ))}
              {issues.length === 0 && anyLoaded && (
                <div className="item"><span className="dot dot-ok" /><span className="muted">Nothing is failing: scan points, feeds, scans, ingest and the kill switch all read clean.</span></div>
              )}
            </div>
            {health.data && (
              <div className="foot-note">
                Kill switch {health.data.kill_switch_state} · ingest backlog {health.data.ingest_backlog} · computed {ago(health.data.computed_at)}. A blocked scan is a silent-success class; it is named here, not hidden as "nothing found".
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}

function Changed({ f, dot, note }: { f: ChangedFinding; dot: string; note: string }) {
  return (
    <div className="item">
      <span className={`dot dot-${dot}`} />
      <span>
        {f.kev && <span className="kev-badge">KEV</span>}{" "}
        <Link to={`/findings/${f.id}`} className="data">{f.rule}</Link>
        {f.asset_hostname && <span className="muted"> · {f.asset_hostname}</span>}
        <span className="detail faint"> — {note}</span>{" "}
        <span className="when">{ago(f.at)}</span>
      </span>
    </div>
  );
}
