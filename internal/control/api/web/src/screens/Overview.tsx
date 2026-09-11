import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, has } from "../lib/api";
import { useAuth } from "../lib/auth";
import { PageHead } from "../components/PageHead";
import { attention, isKEV, kevInversion, score, tally } from "../lib/console";

// The operator landing (console rung 2): what is worst right now and what is
// not working, from the reads that exist. Rung 1 governs every number here —
// each is reproducible from the list it came from, and a count taken over a
// truncated page says so rather than posing as a fleet total. The two regions
// the spec names that need reads nobody has built (changed-since-last-visit,
// trend over time) are shown as not measured, in their own place.
const PAGE = 200; // the findings read's maximum page

export function Overview() {
  const { session } = useAuth();
  const canFindings = has(session, "finding.read");
  const canScans = has(session, "scan.read");

  const findings = useQuery({
    queryKey: ["findings", `?status=open&limit=${PAGE}`],
    queryFn: () => api.listFindings(`?status=open&limit=${PAGE}`),
    enabled: canFindings,
  });
  const points = useQuery({ queryKey: ["scan-points"], queryFn: () => api.listScanPoints(), enabled: canScans });
  const feeds = useQuery({ queryKey: ["knowledge-freshness"], queryFn: () => api.knowledgeFreshness(), enabled: canFindings });
  const scans = useQuery({ queryKey: ["scans", "?limit=50"], queryFn: () => api.listScans("?limit=50"), enabled: canScans });

  const rows = findings.data?.findings ?? [];
  const complete = findings.data ? findings.data.next_id == null : false;
  const kev = tally(rows, complete, isKEV);
  const open = tally(rows, complete, () => true);
  const worst = rows.slice(0, 5);
  const issues = attention(points.data?.scan_points ?? [], feeds.data?.feeds ?? [], scans.data?.scans ?? []);
  const inversion = kevInversion(worst);

  const qual = (t: { exact: boolean; sample: number }) => (t.exact ? "exact" : `of the first ${t.sample}`);

  return (
    <section>
      <PageHead
        title="Operator overview"
        sub="Every number below is reproducible from the list it came from. A count over a truncated page says so; it is never a fleet total."
        meta={<>as of {new Date().toISOString().slice(0, 16).replace("T", " ")}Z</>}
      />

      <div className="metric-strip">
        <div className="card metric">
          <div className="lbl">KEV on fleet</div>
          <div className="row">
            <span className={`value${kev.value > 0 ? " danger" : ""}`}>{findings.data ? kev.value : "—"}</span>
            <span className="qual">{findings.data ? qual(kev) : ""}</span>
          </div>
          <div className="foot">known-exploited, open</div>
        </div>
        <div className="card metric">
          <div className="lbl">Open findings</div>
          <div className="row">
            <span className="value">{findings.data ? (complete ? open.value : `${open.value}+`) : "—"}</span>
            <span className="qual">{findings.data ? (complete ? "exact" : "page is full; more exist") : ""}</span>
          </div>
          <div className="foot">ordered by priority, not severity</div>
        </div>
        <div className="card metric">
          <div className="lbl">Scan points</div>
          <div className="row">
            <span className="value">{points.data ? points.data.scan_points.filter((p) => p.health === "healthy").length : "—"}</span>
            <span className="qual">{points.data ? `of ${points.data.scan_points.length} healthy` : ""}</span>
          </div>
          <div className="foot">server-synthesised health, not client-inferred</div>
        </div>
        <div className={`card metric${issues.length ? " attention" : ""}`}>
          <div className={`lbl${issues.length ? " warn" : ""}`}>Not working</div>
          <div className="row">
            <span className={`value${issues.length ? " warn" : ""}`}>{points.data || feeds.data ? issues.length : "—"}</span>
            <span className="qual">{issues.length === 1 ? "issue" : "issues"}</span>
          </div>
          <div className="foot">scan points, feeds, failed scans</div>
        </div>
      </div>

      <div className="overview">
        <div className="card section">
          <div className="card-head">
            <span className="lbl">Worst right now</span>
            <span className="aside">priority order · <Link to="/triage">open triage →</Link></span>
          </div>
          {findings.isLoading && <p className="muted">Loading…</p>}
          {findings.error && <p className="error">Could not load findings.</p>}
          {!canFindings && <p className="muted">This account cannot read findings.</p>}
          {findings.data && (
            <div className="worst">
              {worst.map((f) => (
                <div className="frow-line" key={f.id}>
                  <span className={`rail rail-${f.severity}`} />
                  <div>
                    <div className="line1">
                      {f.kev && (
                        <span className={`kev-badge${f.kev_ransomware ? " kev-ransomware" : ""}`}>KEV</span>
                      )}
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
          {inversion && (
            <div className="foot-note">
              A KEV-listed finding above outranks a higher-CVSS one below it. Priority, not severity; that inversion is the point.
            </div>
          )}
          <div className="lbl" style={{ marginTop: "1.25rem" }}>Open findings over time</div>
          <div className="not-measured">
            Not measured yet: a finding-count history read does not exist. A count with no history says nothing about whether you are winning, so this stays visibly empty rather than drawn from a guess.
          </div>
        </div>

        <div className="stack">
          <div className="card section">
            <span className="lbl">Changed since your last visit</span>
            <div className="not-measured">
              Not measured yet: there is no delta read (new or reopened findings, KEV re-rankings, coverage changes). Until one exists, Triage is the current state and Knowledge shows feed freshness.
            </div>
          </div>

          <div className={`card section${issues.length ? " attention" : ""}`}>
            <span className={`lbl${issues.length ? " warn" : ""}`}>Not working{issues.length ? " — attention" : ""}</span>
            {(points.error || feeds.error) && <p className="error">Could not load fleet or feed state.</p>}
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
              {issues.length === 0 && (points.data || feeds.data) && (
                <div className="item"><span className="dot dot-ok" /><span className="muted">Nothing the current reads can see is failing.</span></div>
              )}
            </div>
            <div className="foot-note">
              Not read yet: scans blocked for capacity, ingest backlog, kill-switch state. A blocked scan is a silent-success class; it belongs here once the read exists.
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
