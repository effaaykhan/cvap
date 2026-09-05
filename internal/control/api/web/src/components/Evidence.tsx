import type { Evidence } from "../lib/api";

// The evidence view is the deliverable (constraint 1): an analyst reads the
// stored values the rule branched on and confirms the claim by hand. Each
// evidence record's data map is rendered as key/value rows; when the source
// observation has aged out, that is said plainly rather than shown as a dead
// link (ADR-016).
export function EvidenceBlock({ evidence }: { evidence: Evidence[] }) {
  if (!evidence?.length) return <p className="muted">No evidence recorded.</p>;
  return (
    <div className="evidence">
      {evidence.map((e, i) => (
        <div className="evidence-card" key={i}>
          <div className="evidence-head">
            <span className="tag">{e.type}</span>
            <span className="muted">captured {fmt(e.captured_at)}</span>
          </div>
          <dl>
            {Object.entries(e.data ?? {})
              .sort(([a], [b]) => a.localeCompare(b))
              .map(([k, v]) => (
                <div className="kv" key={k}>
                  <dt>{k}</dt>
                  <dd>{render(v)}</dd>
                </div>
              ))}
          </dl>
          <p className="provenance">
            {e.observation_aged_out ? (
              <span className="muted">
                The observation that produced this evidence has aged out; the evidence above was
                copied at the time and is still complete.
              </span>
            ) : (
              <span className="muted">observation {e.observation_id}</span>
            )}
            {e.has_full_artefact ? " · a larger artefact is stored" : ""}
          </p>
        </div>
      ))}
    </div>
  );
}

function render(v: unknown): string {
  if (Array.isArray(v)) return v.join(", ");
  if (v === null || v === undefined) return "";
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

function fmt(t?: string): string {
  return t ? new Date(t).toLocaleString() : "";
}
