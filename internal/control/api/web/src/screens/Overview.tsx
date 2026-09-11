import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, has, type ChangedFinding } from "../lib/api";
import { useAuth } from "../lib/auth";
import { PageHead } from "../components/PageHead";
import { Trend } from "../components/Trend";
import { HBars, SegmentBar, Sparkline, type SegmentSpec } from "../components/Charts";
import { ago, attention, kevInversion, score } from "../lib/console";

// The operator landing (console rung 2): what is worst right now, what changed,
// what is not working, and the trend (rung 5). Every number is served by Core
// from the same rows the lists page over — the summary read counts exactly,
// the change window is a fixed number of days, and the series is derived from
// first_seen and resolved_at — so nothing here has a life of its own.
const WINDOW = 7;
const TREND = 30;
const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

export function Overview() {
  const { session } = useAuth();
  const canFindings = has(session, "finding.read");
  const canScans = has(session, "scan.read");

  const stats = useQuery({
    queryKey: ["finding-summary", WINDOW, TREND],
    queryFn: () => api.findingSummary(`?days=${WINDOW}&trend_days=${TREND}`),
    enabled: canFindings,
  });
  const worstQ = useQuery({ queryKey: ["findings", "?status=open&limit=5"], queryFn: () => api.listFindings("?status=open&limit=5"), enabled: canFindings });
  const exposure = useQuery({ queryKey: ["exposure"], queryFn: () => api.exposure(), enabled: canFindings });
  const points = useQuery({ queryKey: ["scan-points"], queryFn: () => api.listScanPoints(), enabled: canScans });
  const health = useQuery({ queryKey: ["health"], queryFn: () => api.health(), enabled: canScans });
  const feeds = useQuery({ queryKey: ["knowledge-freshness"], queryFn: () => api.knowledgeFreshness(), enabled: canFindings });
  const scans = useQuery({ queryKey: ["scans", "?limit=50"], queryFn: () => api.listScans("?limit=50"), enabled: canScans });

  const s = stats.data;
  const worst = worstQ.data?.findings ?? [];
  const sps = points.data?.scan_points ?? [];
  const issues = attention(sps, feeds.data?.feeds ?? [], scans.data?.scans ?? [], health.data);
  const anyLoaded = !!(points.data || feeds.data || health.data);
  const fleet: SegmentSpec[] = [
    { key: "healthy", label: "healthy", value: sps.filter((p) => p.health === "healthy").length, tone: "ok" },
    { key: "degraded", label: "degraded", value: sps.filter((p) => p.health === "degraded").length, tone: "warn" },
    { key: "offline", label: "offline", value: sps.filter((p) => p.health === "offline").length, tone: "danger" },
    { key: "other", label: "pending/disabled", value: sps.filter((p) => !["healthy", "degraded", "offline"].includes(p.health)).length, tone: "muted" },
  ];
  const severity: SegmentSpec[] = SEVERITIES.map((k) => ({ key: k, label: k, value: s?.by_severity[k] ?? 0, tone: k }));

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
          <div className="row tile">
            <span className={`value${s && s.kev_open > 0 ? " danger" : ""}`}>{s ? s.kev_open : "—"}</span>
            {s && <Sparkline values={s.trend.map((p) => p.kev)} tone="critical" />}
          </div>
          <div className="foot">
            {s && s.kev_listed_since > 0 ? <span className="delta delta-up">▲ {s.kev_listed_since} newly listed in {WINDOW}d</span> : "known-exploited, open · exact"}
          </div>
        </div>
        <div className="card metric">
          <div className="lbl">Open findings</div>
          <div className="row tile">
            <span className="value">{s ? s.open : "—"}</span>
            {s && <Sparkline values={s.trend.map((p) => p.open)} tone="accent" />}
          </div>
          <div className="foot">
            {s ? (
              <span className="delta">
                {s.new_since > 0 && <span className="delta-up">▲ {s.new_since} new</span>}
                {s.new_since > 0 && s.resolved_since > 0 && " · "}
                {s.resolved_since > 0 && <span className="delta-down">▼ {s.resolved_since} resolved</span>}
                {s.new_since === 0 && s.resolved_since === 0 && <span className="faint">no change in {WINDOW}d</span>}
              </span>
            ) : "ordered by priority, not severity"}
          </div>
        </div>
        <div className="card metric">
          <div className="lbl">Scan points</div>
          <div className="row tile">
            <span className="value">{points.data ? fleet[0].value : "—"}</span>
            <span className="qual">{points.data ? `of ${sps.length} healthy` : ""}</span>
          </div>
          {points.data && <div className="fleet"><SegmentBar segments={fleet} height={6} /></div>}
        </div>
        <div className={`card metric${issues.length ? " attention" : ""}`}>
          <div className={`lbl${issues.length ? " warn" : ""}`}>Not working</div>
          <div className="row tile">
            <span className={`value${issues.length ? " warn" : ""}`}>{anyLoaded ? issues.length : "—"}</span>
            <span className="qual">{issues.length === 1 ? "issue" : "issues"}</span>
          </div>
          <div className="foot">
            {health.data?.blocked_scans.length ? `${health.data.blocked_scans.length} blocked · ` : ""}
            {health.data?.kill_switch_state === "active" ? "kill switch ACTIVE · " : ""}
            kill switch, scans, backlog, fleet, feeds
          </div>
        </div>
      </div>

      <div className="dist-grid">
        <div className="card section">
          <div className="card-head">
            <span className="lbl">Open findings by severity</span>
            <span className="aside">{s ? `${s.open} open · exact` : ""}</span>
          </div>
          {stats.isLoading && <p className="muted">Loading…</p>}
          {s && <SegmentBar segments={severity} height={12} />}
          <div className="foot-note">Severity is the rule's own scale. It orders nothing here: the triage list is ordered by priority, where a KEV listing outranks severity.</div>
        </div>
        <div className="card section">
          <div className="card-head">
            <span className="lbl">Exposure by zone</span>
            <span className="aside"><Link to="/exposure">full table →</Link></span>
          </div>
          {exposure.isLoading && <p className="muted">Loading…</p>}
          {exposure.error && <p className="error">Could not load exposure.</p>}
          {exposure.data && exposure.data.zones.length > 0 && (
            <HBars rows={exposure.data.zones.map((z) => ({
              key: z.zone_id, label: z.zone_name || z.zone_id.slice(0, 8), sub: z.zone_type,
              segments: SEVERITIES.map((k) => ({ key: k, label: k, value: z[k], tone: k })),
            }))} />
          )}
          {exposure.data && exposure.data.zones.length === 0 && <p className="empty">No open findings are visible from any zone.</p>}
          <div className="foot-note">Distinct open findings visible from each zone, by severity. Not summable across zones, and zone-derived: which vantage points observed a finding, never a reachability probe.</div>
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
            <div className="foot-note">A KEV-listed finding above outranks a higher-CVSS one below it. Priority, not severity; that inversion is the point.</div>
          )}

          <div className="card-head" style={{ marginTop: "1.25rem" }}>
            <span className="lbl">Open findings — {TREND} days</span>
            {s && <span className="aside">from first-seen and resolved dates · no rollup</span>}
          </div>
          {stats.isLoading && <p className="muted">Loading…</p>}
          {stats.error && <p className="error">Could not load the summary.</p>}
          {s && <Trend points={s.trend} days={s.trend_days} windowDays={WINDOW} />}
        </div>

        <div className="stack">
          <div className="card section">
            <div className="card-head">
              <span className="lbl">Changed in the last {WINDOW} days</span>
              {s && <span className="aside">fixed window, same list for everyone</span>}
            </div>
            {s && (
              <>
                <div className="change-tiles">
                  <div className={`change-tile${s.new_since ? " warn" : ""}`}><div className="n">{s.new_since}</div><div className="k">new</div></div>
                  <div className={`change-tile${s.resolved_since ? " ok" : ""}`}><div className="n">{s.resolved_since}</div><div className="k">resolved</div></div>
                  <div className={`change-tile${s.reopened_since ? " warn" : ""}`}><div className="n">{s.reopened_since}</div><div className="k">reopened</div></div>
                  <div className={`change-tile${s.kev_listed_since ? " danger" : ""}`}><div className="n">{s.kev_listed_since}</div><div className="k">KEV listed</div></div>
                </div>
                <div className="changed">
                  {s.kev_listed_items.map((f) => <Changed key={"k" + f.id} f={f} dot="danger" note="newly listed in KEV — re-ranked" />)}
                  {s.new_items.filter((n) => !s.kev_listed_items.some((k) => k.id === n.id)).map((f) => <Changed key={f.id} f={f} dot={f.severity === "critical" || f.severity === "high" ? "warn" : "medium"} note="new" />)}
                  {s.new_since === 0 && s.resolved_since === 0 && s.reopened_since === 0 && s.kev_listed_since === 0 && (
                    <div className="item"><span className="dot dot-muted" /><span className="muted">Nothing changed in the window.</span></div>
                  )}
                </div>
              </>
            )}
          </div>

          <div className={`card section${issues.length ? " attention" : ""}`}>
            <div className="card-head">
              <span className={`lbl${issues.length ? " warn" : ""}`}>Not working{issues.length ? " — attention" : ""}</span>
              <span className="aside"><Link to="/health">health →</Link></span>
            </div>
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
