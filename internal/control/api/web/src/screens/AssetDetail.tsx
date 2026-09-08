import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api } from "../lib/api";

// AttributionSource mirrors the provenance rows the API embeds (ADR-061). The
// API types it as opaque JSON, so it is narrowed here at the one place it is read.
type AttributionSource = {
  service: string;
  port: number;
  family: string;
  role: "contributed" | "agreed" | "ignored";
};

// ReleaseSource mirrors the release provenance rows (ADR-064). Adds a fourth role
// AttributeOS has not: "abstained" — a service that could not vote (no advisory
// analogue, or its version matched no release band), carried with its reason so
// "absence is not evidence" is visible rather than a silent gap.
type ReleaseSource = {
  service: string;
  port: number;
  product: string;
  band?: string;
  role: "contributed" | "agreed" | "ignored" | "abstained";
  reason?: string;
  candidates?: string[];
};

export function AssetDetail() {
  const { id = "" } = useParams();
  const { data: a, isLoading, error } = useQuery({
    queryKey: ["asset", id],
    queryFn: () => api.getAsset(id),
  });
  if (isLoading) return <p>Loading…</p>;
  if (error || !a) return <p className="error">Could not load this asset.</p>;

  const provenance = (a.os_provenance as AttributionSource[] | undefined) ?? [];
  const releaseProvenance = (a.release_provenance as ReleaseSource[] | undefined) ?? [];

  return (
    <section className="detail">
      <p className="crumb"><Link to="/assets">← Assets</Link></p>
      <h1>{a.hostname || a.id}</h1>
      <dl className="facts">
        <div className="kv"><dt>Environment</dt><dd>{a.environment || "—"}</dd></div>
        <div className="kv"><dt>OS attribution</dt><dd>{osAttribution(a.distro_family, a.distro_release ?? undefined, a.os_confidence ?? undefined)}</dd></div>
        <div className="kv"><dt>Criticality</dt><dd>{a.criticality}</dd></div>
        <div className="kv"><dt>Fragile</dt><dd>{a.fragile ? "yes" : "no"}</dd></div>
        <div className="kv"><dt>Open findings</dt><dd>{a.open_findings}</dd></div>
        <div className="kv"><dt>First seen</dt><dd>{fmt(a.first_seen)}</dd></div>
        <div className="kv"><dt>Last seen</dt><dd>{fmt(a.last_seen)}</dd></div>
      </dl>

      {a.distro_family ? (
        <>
          <h2>How the OS was concluded</h2>
          <table className="provenance"><thead><tr><th>Service</th><th>Suggested</th><th>Role</th></tr></thead>
            <tbody>{provenance.map((p, i) => (
              <tr key={i} className={`role-${p.role}`}>
                <td className="data">{p.service}/{p.port}</td>
                <td className="data">{p.family}</td>
                <td>{roleLabel(p.role)}</td>
              </tr>
            ))}</tbody></table>
          <p className="note">
            OS attribution is inferred from service banners the host volunteered, never confirmed —
            a banner is a string the host chose to send. The chain above is why the conclusion was
            reached: which service was believed, which agreed, and which was overruled.
            {!a.distro_release && (
              <> A family with no release cannot be matched to a vendor advisory feed; it marks the host
              as a candidate for credentialed follow-up, not as unattributed.</>
            )}
          </p>
        </>
      ) : null}

      {releaseProvenance.length ? (
        <>
          <h2>How the release was concluded</h2>
          <p className="note">
            {a.distro_release
              ? <>Resolved release: <span className="data">{a.distro_release}</span>{releaseConfidence(a.release_confidence ?? undefined)} — the confidence is how corroborated the answer is: more agreeing services, and no dissent, is a stronger claim (ADR-065).</>
              : <>No release resolved — the votes below did not agree enough (family-only).</>}
          </p>
          <table className="provenance"><thead><tr><th>Service</th><th>Observed band</th><th>Points at</th><th>Role</th></tr></thead>
            <tbody>{releaseProvenance.map((p, i) => (
              <tr key={i} className={`role-${p.role}`}>
                <td className="data">{p.product} {p.service}/{p.port}</td>
                <td className="data">{p.band || "—"}</td>
                <td className="data">{p.candidates?.length ? p.candidates.join(", ") : (p.reason || "—")}</td>
                <td>{releaseRoleLabel(p.role)}</td>
              </tr>
            ))}</tbody></table>
          <p className="note">
            The release is inferred by matching each service's upstream version band against the
            vendor-advisory keyspace (ADR-064): a band unique to one release is a vote for it.
            Every failure is <em>unresolved</em>, never wrong — a service whose version matches no
            release band, or whose product has no advisory data, <strong>abstains</strong> (shown
            above with its reason) rather than voting against.
            {a.distro_release
              ? <> {" "}Resolved when at least two services agree; here they did.</>
              : <> {" "}Not enough agreeing votes to resolve a release, so the host stays family-only — matchable only once more evidence agrees.</>}
          </p>
        </>
      ) : null}

      <h2>Addresses</h2>
      {a.addresses?.length ? (
        <table><thead><tr><th>IP</th><th>MAC</th><th>Since</th></tr></thead>
          <tbody>{a.addresses.map((ad, i) => (
            <tr key={i}><td className="data">{ad.ip || "—"}</td><td className="data">{ad.mac || "—"}</td><td className="data">{fmt(ad.valid_from)}</td></tr>
          ))}</tbody></table>
      ) : <p className="muted">No current addresses.</p>}

      <h2>Services</h2>
      {a.services?.length ? (
        <>
          <table><thead><tr><th>Port</th><th>Service</th><th>Identification</th><th>Evidence</th></tr></thead>
            <tbody>{a.services.map((s, i) => (
              <tr key={i}>
                <td className="data">{s.port}/{s.protocol}</td>
                <td className="data">{s.service || <span className="unknown">unknown</span>}</td>
                <td className="data">{identification(s.product, s.version)}</td>
                <td className="data">{evidence(s.method, s.version_confidence ?? undefined)}</td>
              </tr>
            ))}</tbody></table>
          <p className="note">
            Services are identified from what they say on connect. “Apache 2.2.8 (banner, high)”
            was read from the service’s own banner; “unknown” means it answered but named no
            product, which is a service seen, not a version confirmed.
          </p>
        </>
      ) : <p className="muted">No services observed.</p>}
    </section>
  );
}

// osAttribution renders the three-state model (ADR-061) so each state LOOKS like
// what it is: resolved reads as a fact, family-only reads as explicitly
// incomplete, and no attribution reads as absent — never as a confident guess.
function osAttribution(family?: string, release?: string, confidence?: number) {
  if (!family) return <span className="unknown">unknown · no attribution</span>;
  const b = band(confidence);
  const conf = confidence != null ? <span className={`conf conf-${b}`}> · {b} ({confidence.toFixed(2)})</span> : null;
  if (release) {
    return <>{family} {release}{conf}</>;
  }
  return (
    <>
      <span className="data">{family}</span>{" "}
      <span className="hint">· release unknown, unmatched for advisories</span>
      {conf}
    </>
  );
}

// identification renders "Apache 2.2.8", "Apache" (product, no version) or a
// softmatch "unknown" — product-empty is a real answer, not a failure.
function identification(product?: string, version?: string) {
  const s = [product, version].filter(Boolean).join(" ");
  return s || <span className="unknown">unknown</span>;
}

// evidence renders the provenance of a service identification: how it was learned
// and how much it is believed — the difference the finding pipeline weights.
function evidence(method?: string, confidence?: number) {
  const parts: string[] = [];
  if (method) parts.push(method);
  const b = band(confidence);
  if (b) parts.push(b);
  if (!parts.length) return <span className="muted">—</span>;
  return <span className="hint">{parts.join(", ")}</span>;
}

function roleLabel(role: AttributionSource["role"]): string {
  switch (role) {
    case "contributed": return "concluded from";
    case "agreed": return "agreed";
    case "ignored": return "overruled";
  }
}

// releaseConfidence renders the resolved release's confidence as a band + value,
// the same treatment os_confidence gets. Without this the number is stored,
// served and never shown — the write-carry-store-drop shape (§5.6), which the
// ADR-065 tiering makes load-bearing: a two-vote resolution must read as weaker
// than a four-vote one, and that only helps if it is on screen.
function releaseConfidence(confidence?: number) {
  if (confidence == null) return null;
  const b = band(confidence);
  return <span className={`conf conf-${b}`}> · {b} ({confidence.toFixed(2)})</span>;
}

function releaseRoleLabel(role: ReleaseSource["role"]): string {
  switch (role) {
    case "contributed": return "voted";
    case "agreed": return "agreed (ambiguous)";
    case "ignored": return "dissented";
    case "abstained": return "abstained";
  }
}

function band(c?: number): "high" | "medium" | "low" | "" {
  if (c == null) return "";
  if (c >= 0.9) return "high";
  if (c >= 0.7) return "medium";
  return "low";
}

function fmt(t?: string): string { return t ? new Date(t).toLocaleString() : "—"; }
