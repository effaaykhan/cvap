import { useQuery } from "@tanstack/react-query";
import { api, type KnowledgeFeed } from "../lib/api";

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
    </section>
  );
}
