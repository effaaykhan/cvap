import { useQuery } from "@tanstack/react-query";
import { api, type KnowledgeFeed, type ReleaseCoverage } from "../lib/api";

// Coverage state labels (B29). "Out of coverage" means the release is past its
// advisory window — the keyspace stopped accumulating for it, so a no-match on a
// host of that release is cannot-know, not clean.
const COVERAGE_LABEL: Record<string, string> = {
  covered: "Covered",
  out_of_coverage: "Out of coverage",
  unknown: "Unknown",
};

// Knowledge feed freshness (P3.2). Whether the vendor-advisory data behind
// advisory-matched findings is current. The `state` word is the SERVER's verdict,
// computed against each feed's own staleness threshold stored in the data — a
// stale feed means matching is under-reporting (a silent false negative), so this
// panel renders the state rather than making the operator judge a timestamp.
const STATE_LABEL: Record<string, string> = {
  current: "Current",
  stale: "Stale",
  never: "Never fetched",
};

function fetchedAgo(iso: string | null | undefined): string {
  if (!iso) return "never";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "unknown";
  const secs = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (secs < 90) return `${secs}s ago`;
  const mins = Math.round(secs / 60);
  if (mins < 90) return `${mins}m ago`;
  const hours = Math.round(mins / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

function thresholdText(seconds: number): string {
  const days = Math.round(seconds / 86400);
  if (days >= 1) return `${days}d`;
  return `${Math.round(seconds / 3600)}h`;
}

function CoverageRow({ c }: { c: ReleaseCoverage }) {
  // covered -> ok, out_of_coverage -> danger, unknown -> muted; reuse the
  // freshness badge classes so the two states read the same way.
  const cls =
    c.state === "covered" ? "freshness-current" : c.state === "out_of_coverage" ? "freshness-stale" : "freshness-never";
  return (
    <tr>
      <td className="data">{c.release}</td>
      <td>
        <span className={`freshness ${cls}`}>{COVERAGE_LABEL[c.state] ?? c.state}</span>
      </td>
      <td className="muted">{c.esm_expires || <span className="faint">—</span>}</td>
      <td className="muted">{c.newest_advisory_at || <span className="faint">—</span>}</td>
      <td className="muted">{c.coverage_source || <span className="faint">—</span>}</td>
    </tr>
  );
}

function FeedRow({ f }: { f: KnowledgeFeed }) {
  return (
    <tr>
      <td>{f.feed}</td>
      <td>
        {/* The state is the server's answer; the class drives the badge colour. */}
        <span className={`freshness freshness-${f.state}`}>{STATE_LABEL[f.state] ?? f.state}</span>
      </td>
      <td className="num">{f.advisory_count}</td>
      <td className="muted">{fetchedAgo(f.last_fetched_at)}</td>
      <td className="muted">{thresholdText(f.staleness_threshold_seconds)}</td>
      <td className="muted">{f.source_etag || <span className="faint">—</span>}</td>
    </tr>
  );
}

export function Knowledge() {
  const { data, isLoading, error } = useQuery({
    queryKey: ["knowledge-freshness"],
    queryFn: () => api.knowledgeFreshness(),
  });

  const anyStale = data?.feeds.some((f) => f.state === "stale" || f.state === "never");
  const anyOutOfCoverage = data?.coverage?.some((c) => c.state === "out_of_coverage");

  return (
    <section>
      <h1>Knowledge feeds</h1>
      <p className="note">
        Vendor-advisory feeds behind advisory-matched findings. <strong>Stale</strong> means the
        last fetch is older than the feed's own freshness threshold, so matching against it is
        under-reporting — a stale feed is a source of missed findings, not just old data.
      </p>
      {isLoading && <p>Loading…</p>}
      {error && <p className="error">Could not load feed freshness.</p>}
      {anyStale && (
        <p className="error">
          One or more feeds are stale or have never been fetched. Advisory matching may be missing
          recent vulnerabilities until they are refreshed.
        </p>
      )}
      {data && (
        <table>
          <thead>
            <tr>
              <th>Feed</th>
              <th>State</th>
              <th className="num">Advisories</th>
              <th>Last fetched</th>
              <th>Threshold</th>
              <th>Version (ETag)</th>
            </tr>
          </thead>
          <tbody>
            {data.feeds.map((f) => (
              <FeedRow key={f.feed} f={f} />
            ))}
            {data.feeds.length === 0 && (
              <tr className="empty">
                <td colSpan={6}>No advisory feeds ingested yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      )}

      <h2>Release coverage</h2>
      <p className="note">
        Each ingested release's advisory window. <strong>Out of coverage</strong> means the
        release is past its support/ESM end — the feed no longer issues advisories for it, so a
        host on it can carry exposure the keyspace cannot know about. On such a host, a result
        with no advisory match means <strong>cannot-know</strong>, not clean (B29). Where the feed
        gave only a placeholder date (<span className="data">feed-degenerate</span>), the newest
        advisory column is the honest coverage end.
      </p>
      {anyOutOfCoverage && (
        <p className="error">
          One or more ingested releases are out of advisory coverage. Hosts on those releases
          cannot be assessed for vulnerabilities disclosed after their window closed.
        </p>
      )}
      {data && (
        <table>
          <thead>
            <tr>
              <th>Release</th>
              <th>Coverage</th>
              <th>ESM / support end</th>
              <th>Newest advisory</th>
              <th>Source</th>
            </tr>
          </thead>
          <tbody>
            {(data.coverage ?? []).map((c) => (
              <CoverageRow key={c.release} c={c} />
            ))}
            {(data.coverage ?? []).length === 0 && (
              <tr className="empty">
                <td colSpan={5}>No release coverage recorded yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      )}
    </section>
  );
}
