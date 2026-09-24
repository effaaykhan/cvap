import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, has, type IdentityKey } from "../lib/api";
import { useAuth } from "../lib/auth";
import { advisory, score, exactRead, provenanceAge, ago, fmtTime, isSeenOnly } from "../lib/console";

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

  // Provenance has two shapes (ADR-095): an ARRAY of banner votes when the
  // attribution was inferred, an OBJECT with a source and read_at when it was
  // read on the host. An exact read outranks any later inference and carries its
  // age, so the page says when it was read rather than showing a vote table.
  const osExact = exactRead(a.os_provenance);
  const releaseExact = exactRead(a.release_provenance);
  const provenance = Array.isArray(a.os_provenance) ? (a.os_provenance as unknown as AttributionSource[]) : [];
  const releaseProvenance = Array.isArray(a.release_provenance) ? (a.release_provenance as unknown as ReleaseSource[]) : [];

  return (
    <section className="detail">
      <p className="crumb"><Link to="/assets">← Systems</Link></p>
      <div className="row-between">
        <h1>{a.hostname || a.address || a.id}</h1>
        <span className={`chip chip-${advisory(a.advisory_status).tone === "critical" ? "danger" : advisory(a.advisory_status).tone}`}>{advisory(a.advisory_status).label}</span>
      </div>
      <p className="muted small" style={{ marginTop: "-.5rem" }}>
        {a.open_findings} open finding{a.open_findings === 1 ? "" : "s"} · posture <b>{advisory(a.advisory_status).label}</b>: {advisory(a.advisory_status).why}.
      </p>
      <FindingsOnAsset assetID={a.id} count={a.open_findings} />
      <dl className="facts">
        <div className="kv"><dt>Environment</dt><dd>{a.environment || "—"}</dd></div>
        <div className="kv"><dt>OS attribution</dt><dd>{osAttribution(a.distro_family, a.distro_release ?? undefined, a.os_confidence ?? undefined)}</dd></div>
        {a.kernel && (
          <div className="kv"><dt>Running kernel</dt><dd>
            <span className="data">{a.kernel.running_release || "not read"}</span>
            {a.kernel.reboot_pending === true && <span className="chip chip-warn" style={{ marginLeft: 8 }}>reboot pending</span>}
            {a.kernel.reboot_pending === false && <span className="chip chip-ok" style={{ marginLeft: 8 }}>current</span>}
            {a.kernel.reboot_pending == null && <span className="chip chip-muted" style={{ marginLeft: 8 }}>unjudged</span>}
          </dd></div>
        )}
        <div className="kv"><dt>Criticality</dt><dd>{a.criticality}</dd></div>
        <div className="kv"><dt>Fragile</dt><dd>{a.fragile ? "yes" : "no"}</dd></div>
        <div className="kv"><dt>Open findings</dt><dd>{a.open_findings}</dd></div>
        <div className="kv"><dt>Advisory status</dt><dd>{advisoryStatus(a.advisory_status)}</dd></div>
        <div className="kv"><dt>First seen</dt><dd>{fmt(a.first_seen)}</dd></div>
        <div className="kv"><dt>Last seen</dt><dd>{fmt(a.last_seen)}</dd></div>
      </dl>

      {(osExact || releaseExact) && <ClearPin assetID={a.id} />}
      {a.distro_family && osExact ? (
        <>
          <h2>How the OS was concluded</h2>
          <p className="note">
            Read on the host from <span className="data">/etc/os-release</span> by a credentialed pass
            {osExact.readAt ? <> on <span className="data">{fmt(osExact.readAt)}</span> {provenanceAge(osExact.readAt) ? ` (${provenanceAge(osExact.readAt)})` : ""}</> : null}.
            An exact read outranks anything a banner suggests, however recent the banner (ADR-095); if the host
            stops answering credentialed, this value stays and its age grows rather than reverting to a guess.
          </p>
        </>
      ) : null}
      {a.distro_family && !osExact ? (
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

      {releaseExact ? (
        <>
          <h2>How the release was concluded</h2>
          <p className="note">
            Resolved release: <span className="data">{a.distro_release}</span>{releaseConfidence(a.release_confidence ?? undefined)} — read exactly
            from the host{releaseExact.readAt ? <> on <span className="data">{fmt(releaseExact.readAt)}</span> {provenanceAge(releaseExact.readAt) ? ` (${provenanceAge(releaseExact.readAt)})` : ""}</> : null}, not
            inferred from version bands. A later band vote never overwrites this (ADR-095).
          </p>
        </>
      ) : null}
      {!releaseExact && releaseProvenance.length ? (
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

      {a.release_coverage_state === "out_of_coverage" && (
        <p className="error">
          ⚠ This host's release{a.distro_release ? <> (<span className="data">{a.distro_release}</span>)</> : null} is
          <strong> out of advisory coverage</strong>
          {a.release_coverage_end ? <> since <span className="data">{a.release_coverage_end}</span></> : null}. The
          advisory feed no longer issues advisories for it, so a result with no advisory match here means
          <strong> cannot-know, not clean</strong> — this host may carry vulnerabilities disclosed after its window
          closed that the keyspace cannot see (B29). Treat an empty finding list as "not assessed", not "safe".
        </p>
      )}
      {a.release_coverage_state === "unknown" && a.distro_release && (
        <p className="note">
          The advisory coverage window for <span className="data">{a.distro_release}</span> is not recorded, so
          whether this host is fully assessable cannot be confirmed. A no-advisory result is treated as cannot-know.
        </p>
      )}

      <h2>Addresses</h2>
      {a.addresses?.length ? (
        <table><thead><tr><th>IP</th><th>MAC</th><th>Since</th></tr></thead>
          <tbody>{a.addresses.map((ad, i) => (
            <tr key={i}><td className="data">{ad.ip || "—"}</td><td className="data">{ad.mac || "—"}</td><td className="data">{fmt(ad.valid_from)}</td></tr>
          ))}</tbody></table>
      ) : <p className="muted">No current addresses.</p>}

      {a.kernel && a.kernel.installed.length > 0 && (
        <>
          <h2>Installed kernels</h2>
          <p className="note">
            From the credentialed read on <span className="data">{fmtTime(a.kernel.read_at)}</span>. A kernel package is matched against advisories
            only at the version that is running (ADR-099); the others are inventory. A newer version installed and not running is a reboot pending —
            the fix is on disk and the vulnerable kernel still executes.
          </p>
          <table><thead><tr><th>Package</th><th>Version</th><th>State</th></tr></thead>
            <tbody>{a.kernel.installed.map((k, i) => (
              <tr key={i}><td className="data">{k.binary}</td><td className="data">{k.version}</td>
                <td><span className={`chip ${k.state === "kernel-running" ? "chip-ok" : k.state === "kernel-unknown" ? "chip-muted" : "chip-muted"}`}>
                  {k.state === "kernel-running" ? "running" : k.state === "kernel-installed-not-running" ? "installed, not running" : "unknown (no uname on the read)"}
                </span></td></tr>
            ))}</tbody></table>
        </>
      )}
      <IdentityKeys assetID={a.id} keys={a.identity_keys ?? []} total={a.identity_keys_total ?? 0} />

      <Timeline assetID={a.id} />

      <h2>Open ports and services</h2>
      {a.services?.length ? (
        <>
          <table><thead><tr><th>Port</th><th>Service</th><th>Identification</th><th>Evidence</th></tr></thead>
            <tbody>{a.services.map((s, i) => (
              <tr key={i}>
                <td className="data">{s.port}/{s.protocol}</td>
                <td className="data">
                  {isSeenOnly(s.method)
                    ? <span className="unknown">open, unidentified</span>
                    : s.service || <span className="unknown">unknown</span>}
                </td>
                <td className="data">{isSeenOnly(s.method) ? "—" : identification(s.product, s.version)}</td>
                <td className="data">
                  {isSeenOnly(s.method)
                    ? <span className="unknown">port scan only</span>
                    : evidence(s.method, s.version_confidence ?? undefined)}
                </td>
              </tr>
            ))}</tbody></table>
          <p className="note">
            Services are identified from what they say on connect. “Apache 2.2.8 (banner, high)”
            was read from the service’s own banner; “unknown” means it answered but named no
            product, which is a service seen, not a version confirmed.
          </p>
          <p className="note">
            “open, unidentified” means a discovery scan saw the port answer and nothing has
            probed it since — attack surface, not an identification. A fingerprint scan over
            this host upgrades those rows in place.
          </p>
        </>
      ) : <p className="muted">No open ports or services observed.</p>}
    </section>
  );
}

// advisoryStatus renders the server-owned verdict (ADR-068). "Clean" is reachable
// here ONLY from advisory_status === "clean" — there is no path from an empty
// finding list to the word clean, which is the point: cannot-know cannot be shown
// as clean by a client that forgets to check coverage.
function advisoryStatus(status?: string) {
  switch (status) {
    case "clean":
      return <span className="freshness freshness-current">No known advisory vulnerabilities</span>;
    case "vulnerable":
      return <span className="freshness freshness-stale">Vulnerable</span>;
    case "cannot_know":
      return <span className="freshness freshness-stale">Cannot assess — release out of coverage</span>;
    case "no_release":
      return <span className="freshness freshness-never">Unmatched — no release resolved</span>;
    default:
      return <span className="muted">—</span>;
  }
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

// The "why" for this system: its open findings in priority order, each with
// the rule, the severity word, KEV, EPSS and CVSS, and the evidence one click
// away — the same rows the triage list pages over, filtered to this asset.
function FindingsOnAsset({ assetID, count }: { assetID: string; count: number }) {
  const q = `?asset_id=${assetID}&status=open&limit=200`;
  const { data, isLoading, error } = useQuery({ queryKey: ["findings", q], queryFn: () => api.listFindings(q) });
  return (
    <>
      <h2>Findings on this system</h2>
      {isLoading && <p className="muted">Loading…</p>}
      {error && <p className="error">Could not load this system's findings.</p>}
      {data && data.findings.length === 0 && (
        <p className="muted">{count === 0 ? "No open findings." : "No open findings in this page."}</p>
      )}
      {data && data.findings.length > 0 && (
        <table>
          <thead><tr><th>Priority</th><th>Severity</th><th>Finding</th><th>Where</th><th className="num">EPSS</th><th className="num">CVSS</th><th>Confidence</th></tr></thead>
          <tbody>
            {data.findings.map((f, i) => (
              <tr key={f.id} className={`frow frow-${f.severity}`}>
                <td><span className="rank">#{i + 1}</span>{f.kev && <span className={`kev-badge${f.kev_ransomware ? " kev-ransomware" : ""}`}>KEV</span>} <span className="priority-basis">{f.priority_basis}</span></td>
                <td><span className={`sev sev-${f.severity}`}>{f.severity}</span></td>
                <td className="finding-cell"><Link to={`/findings/${f.id}`}>{f.rule}</Link><span className="cat small">{f.category}</span></td>
                <td className="data">{f.instance_locator || "—"}</td>
                <td className="num">{score(f.epss, 5)}</td>
                <td className="num">{score(f.cvss, 1)}</td>
                <td className="data">{(f.confidence ?? 0).toFixed(2)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {data && data.next_id && <p className="faint small">Showing the first 200 by priority; the triage view can narrow further.</p>}
    </>
  );
}

// What the credentialed engine would make of this asset's keys right now
// (ADR-094, ADR-096, ADR-097; B39): sightings still needed, or a rotated key
// waiting for an operator's word. Confirming verifies nothing — the probe
// checks no possession (B44) — it records a decision and who took it.
function IdentityKeys({ assetID, keys, total }: { assetID: string; keys: IdentityKey[]; total: number }) {
  const { session } = useAuth();
  const qc = useQueryClient();
  const [reason, setReason] = useState("");
  const [outcome, setOutcome] = useState("");
  // Only the keys the operator ticks are confirmed: the rotated set is one an
  // attacker helps compose, and blessing all of it for one genuine rotation
  // was measured handing a planted key the credentialed dial.
  const waiting = keys.filter((k) => k.provenance === "rotation" || k.provenance === "lapsed").map((k) => `${k.key_type} ${k.fingerprint}`);
  const [ticked, setTicked] = useState<Record<string, boolean>>({});
  const chosen = waiting.filter((w) => ticked[w]);
  const confirm = useMutation({
    mutationFn: () => api.confirmIdentity(assetID, chosen, reason),
    onSuccess: (res) => {
      setOutcome(`Confirmed ${res.keys_confirmed.length} of ${res.keys_confirmed.length + res.keys_remaining_total}.`);
      setTicked({});
      void qc.invalidateQueries({ queryKey: ["asset", assetID] });
    },
    onError: (e: Error) => setOutcome(e.message),
  });
  const needsWord = waiting.length > 0;
  return (
    <>
      <h2>Identity keys</h2>
      {total > keys.length && <p className="small">{total} live keys; the {keys.length} shown are all this page carries. A key past this page cannot be confirmed here.</p>}
      {keys.length === 0 ? <p className="muted">No identity key on record. A host first seen without one gains it on its next fingerprint pass (ADR-093).</p> : (
        <table><thead><tr>{needsWord && <th>Confirm</th>}<th>Key</th><th>Service</th><th>Fingerprint</th><th>Seen at</th><th>Scans</th><th>Credentialed trust</th></tr></thead>
          <tbody>{keys.map((k, i) => (
            <tr key={i}>
              {needsWord && <td>{(k.provenance === "rotation" || k.provenance === "lapsed") && (
                <input type="checkbox" checked={!!ticked[`${k.key_type} ${k.fingerprint}`]}
                  onChange={(e) => setTicked((t) => ({ ...t, [`${k.key_type} ${k.fingerprint}`]: e.target.checked }))} />
              )}</td>}
              <td>{k.key_type}</td>
              <td className="data">{k.source || "—"}</td>
              <td className="data">{k.fingerprint}</td>
              <td className="data">{k.address ? `${k.address} · ${k.last_seen_at ? ago(k.last_seen_at) : ""}` : "—"}</td>
              <td className="data">{k.scans_seen}</td>
              <td>
                <span className={`chip ${k.trust_material ? "chip-ok" : k.provenance === "rotation" || k.provenance === "lapsed" ? "chip-warn" : "chip-muted"}`}>
                  {k.trust_material ? "trusted" : k.provenance === "rotation" || k.provenance === "lapsed" ? "needs confirmation" : "not yet"}
                </span>
                <span className="faint small"> {k.note}</span>
              </td>
            </tr>
          ))}</tbody></table>
      )}
      {needsWord && (has(session, "identity.resolve") ? (
        <div className="row" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <input placeholder="Why this key is the host's own (recorded with your name)" value={reason} onChange={(e) => setReason(e.target.value)} style={{ minWidth: 320 }} />
          <button className="btn small-btn" disabled={confirm.isPending || !reason || chosen.length === 0} onClick={() => confirm.mutate()}>
            Confirm {chosen.length === 1 ? "this key" : `${chosen.length} keys`}
          </button>
          {outcome && <span className="small">{outcome}</span>}
          <span className="faint small">Confirming hands the credentialed dial to whoever holds this key. It verifies nothing (B44).</span>
        </div>
      ) : (
        <p className="faint small">A rotated key waits for an operator with identity.resolve to confirm it; until then credentialed scans of this host refuse.</p>
      ))}
    </>
  );
}

// Timeline: every audit event keyed to this asset, where the asset is (ADR-100):
// contests, rotations, expiries, the operator's decisions and refusals, cleared
// attributions. Newest first.
function Timeline({ assetID }: { assetID: string }) {
  const { data, isLoading } = useQuery({ queryKey: ["asset-events", assetID], queryFn: () => api.assetEvents(assetID) });
  const events = data?.events ?? [];
  return (
    <>
      <h2>Timeline</h2>
      {isLoading ? <p className="muted">Loading…</p> : events.length === 0 ? (
        <p className="muted">Nothing recorded against this system yet. Contests, rotations, decisions and refusals land here.</p>
      ) : (
        <table><thead><tr><th>When</th><th>What</th><th>Who</th><th>Detail</th></tr></thead>
          <tbody>{events.map((e) => (
            <tr key={e.id}>
              <td className="data">{fmtTime(e.occurred_at)}</td>
              <td className="data">{e.action}</td>
              <td className="data">{e.actor_type === "user" ? (e.actor_id ? e.actor_id.slice(0, 8) : "operator (cli)") : e.actor_type}</td>
              <td className="small">{summarise(e.detail)}</td>
            </tr>
          ))}</tbody></table>
      )}
    </>
  );
}

// summarise renders an event's detail as "key: value" pairs, skipping the notes
// the API writes for auditors reading the raw log.
function summarise(detail?: Record<string, unknown>): string {
  if (!detail) return "";
  return Object.entries(detail)
    .filter(([k, v]) => k !== "note" && v !== null && v !== undefined && v !== "")
    .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : typeof v === "object" ? JSON.stringify(v) : String(v)}`)
    .join(" · ");
}

// ClearPin lifts an exact attribution's rank (ADR-095, ADR-100): the values stay
// until the next sweep re-derives them. For a host that lied within the token
// grammar; an operator with identity.resolve, with a reason.
function ClearPin({ assetID }: { assetID: string }) {
  const { session } = useAuth();
  const qc = useQueryClient();
  const [reason, setReason] = useState("");
  const [outcome, setOutcome] = useState("");
  const clear = useMutation({
    mutationFn: () => api.clearAttribution(assetID, reason),
    onSuccess: (res) => {
      setOutcome(`Cleared: ${res.cleared.join(", ")}. The next sweep re-derives.`);
      void qc.invalidateQueries({ queryKey: ["asset", assetID] });
      void qc.invalidateQueries({ queryKey: ["asset-events", assetID] });
    },
    onError: (e: Error) => setOutcome(e.message),
  });
  if (!has(session, "identity.resolve")) return null;
  return (
    <div className="row small" style={{ gap: 8, alignItems: "center", flexWrap: "wrap" }}>
      <span className="faint">This attribution was read on the host and outranks inference. If the host lied:</span>
      <input placeholder="Why (recorded with your name)" value={reason} onChange={(e) => setReason(e.target.value)} style={{ minWidth: 260 }} />
      <button className="btn small-btn" disabled={clear.isPending || !reason} onClick={() => clear.mutate()}>Clear the pinned attribution</button>
      {outcome && <span>{outcome}</span>}
    </div>
  );
}
