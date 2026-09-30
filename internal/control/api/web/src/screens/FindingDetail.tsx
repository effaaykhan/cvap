import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { api, type Technique } from "../lib/api";
import { EvidenceBlock } from "../components/Evidence";
import { Confidence } from "../components/Confidence";

// The finding detail: read the finding, its rule, the evidence that produced it,
// and the zones it is exposed from — and confirm the claim by hand without
// re-scanning (constraint 1, week 6's argument).
export function FindingDetail() {
  const { id = "" } = useParams();
  const { data: f, isLoading, error } = useQuery({
    queryKey: ["finding", id],
    queryFn: () => api.getFinding(id),
  });

  if (isLoading) return <p>Loading…</p>;
  if (error || !f) return <p className="error">Could not load this finding.</p>;

  return (
    <section className="detail detail-wide">
      <p className="crumb"><Link to="/triage">← Triage</Link></p>
      <div className="row-between">
        <h1><span className={`sev sev-${f.severity}`}>{f.severity}</span> {f.rule}</h1>
        <span className="tag">{f.status}</span>
      </div>
      {/* The page's three visual registers, used consistently below: a fact
          grid for metadata, a structured card for ATT&CK and raw evidence,
          and a plain section for prose. */}
      <h2>Finding facts</h2>
      <dl className="facts">
        <div className="kv"><dt>Asset</dt><dd><Link to={`/assets/${f.asset_id}`}>{f.asset_hostname || f.asset_id}</Link></dd></div>
        <div className="kv"><dt>Where</dt><dd className="data">{f.instance_locator || "—"}</dd></div>
        <div className="kv"><dt>Category</dt><dd>{f.category}</dd></div>
        <div className="kv"><dt>Confidence</dt><dd><Confidence value={f.confidence} /></dd></div>
      </dl>

      <h2>Finding context</h2>
      <dl className="facts">
        <div className="kv"><dt>Claim</dt><dd>{f.has_vuln_def ? "advisory-matched" : "rule / banner-inferred"}</dd></div>
        <div className="kv"><dt>Source</dt><dd>{f.source}</dd></div>
        {f.cwe && <div className="kv"><dt>CWE</dt><dd>{f.cwe}</dd></div>}
        <div className="kv"><dt>First seen</dt><dd>{fmt(f.first_seen)}</dd></div>
        <div className="kv"><dt>Last seen</dt><dd>{fmt(f.last_seen)}</dd></div>
      </dl>

      <h2>Dedup key</h2>
      {/* Long by construction (ADR-010: the identity this finding persists
          under across scans) — a full-width line that wraps freely, never
          crushed into a fact cell. */}
      <code className="dedup-val">{f.dedup_key}</code>

      {/* Priority for every finding, not only advisory-matched ones. All
          four cells always render so the section keeps one shape; a finding
          without a vuln def shows an em dash for EPSS/CVSS because those
          scores exist only against a CVE — the dash is "does not apply
          here", distinct from the unscored/unknown wording a matched
          finding gets (ADR-069). */}
      <h2>Priority</h2>
      <dl className="facts">
            <div className="kv">
              <dt>Exploitation</dt>
              <dd>
                {f.kev ? (
                  <>
                    <span className={`kev-badge${f.kev_ransomware ? " kev-ransomware" : ""}`}>KEV</span>{" "}
                    In CISA KEV — confirmed exploited in the wild
                    {f.kev_ransomware && " (known ransomware use)"}
                    {f.kev_date_added && <span className="muted"> · added {f.kev_date_added}</span>}
                  </>
                ) : (
                  // Absence is not evidence (ADR-069): not listed, NOT known-unexploited.
                  <span className="muted">Not listed in CISA KEV (unlisted — not known-unexploited)</span>
                )}
              </dd>
            </div>
            <div className="kv"><dt>Basis</dt><dd>{f.priority_basis}</dd></div>
            <div className="kv">
              <dt>EPSS</dt>
              <dd>
                {f.epss != null ? (
                  <>
                    {f.epss.toFixed(5)}
                    {f.epss_percentile != null && (
                      <span className="muted"> · {(f.epss_percentile * 100).toFixed(1)}th percentile</span>
                    )}
                  </>
                ) : f.has_vuln_def ? (
                  <span className="muted">Unscored (no signal — not low probability)</span>
                ) : (
                  <span className="muted" title="no vulnerability definition, so EPSS has nothing to score">—</span>
                )}
              </dd>
            </div>
            <div className="kv">
              <dt>CVSS</dt>
              <dd>
                {f.cvss != null ? (
                  f.cvss
                ) : f.has_vuln_def ? (
                  <span className="muted">Unknown</span>
                ) : (
                  <span className="muted" title="no vulnerability definition, so no CVSS vector exists">—</span>
                )}
              </dd>
            </div>
      </dl>

      <h2>ATT&amp;CK techniques</h2>
      {f.attack_techniques.length ? (
        <>
          {/* The wording contract (ADR-105 decision 3): these are inferences
              about what the weakness would enable. CVAP has not observed any
              of them in use and cannot (non-negotiable #9). */}
          <p className="muted">
            Inferred from the weakness — techniques an adversary could use it for.
            CVAP has not observed any of these techniques in use.
          </p>
          <div className="techniques">
            {f.attack_techniques.map((t) => (
              <TechniqueCard key={`${t.source}-${t.id}`} t={t} />
            ))}
          </div>
        </>
      ) : (
        <>
          {/* [] is "no mapping held", never "no technique applies" (decision 4). */}
          <p className="tech-unmapped">Unmapped</p>
          <p className="muted">CVAP holds no mapping for this finding.</p>
        </>
      )}

      {f.remediation && (
        <>
          <h2>Remediation</h2>
          <p>{f.remediation}</p>
        </>
      )}

      <h2>Evidence</h2>
      <p className="muted">The values the rule read, so you can confirm this without re-scanning.</p>
      <EvidenceBlock evidence={f.evidence ?? []} />

      <h2>Exposure</h2>
      {f.exposures?.length ? (
        <table>
          <thead><tr><th>Zone</th><th>Type</th><th>Last confirmed</th></tr></thead>
          <tbody>
            {f.exposures.map((e, i) => (
              <tr key={i}>
                <td>{e.zone_name || e.zone_id}</td>
                <td>{e.zone_type}</td>
                <td>{fmt(e.last_confirmed)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="muted">No zone exposure recorded.</p>
      )}
      <p className="note note-wide">
        Exposure lists the zones this finding was seen from. It is not an internet-reachability
        assessment — that is not yet computed.
      </p>
    </section>
  );
}

// One inferred technique. The two anchors are different kinds of evidence
// (ADR-105 decision 2) and stay visibly different: a curated rule mapping is
// a judgement someone here made and wrote a rationale for; a CVE mapping is a
// published dataset's judgement, carried with that source's own qualifier.
// Neither is ever styled like severity or priority (decision 5).
function TechniqueCard({ t }: { t: Technique }) {
  return (
    <div className="tech-card">
      <div className="tech-head">
        {t.url ? (
          <a className="tech-id" href={t.url} target="_blank" rel="noreferrer">{t.id}</a>
        ) : (
          <span className="tech-id">{t.id}</span>
        )}
        <span className="tech-name">{t.name}</span>
        <span className="tag">{t.inference}</span>
        <span className="tag">{t.anchor === "rule" ? "curated rule" : t.anchor === "cve" ? "CVE mapping" : t.anchor}</span>
        {t.deprecated && <span className="tag tech-retired">retired</span>}
      </div>
      <div className="tech-meta">
        <span className="tech-tactics">{t.tactics.map((x) => x.replace(/-/g, " ")).join(" · ")}</span>
        <span> · source: {t.source}</span>
        {t.mapping_type && <span> · {t.mapping_type}</span>}
        {/* The source's confidence, only when it published one — no bar, no
            band, no substitute number when it is absent (ADR-105). */}
        {t.confidence != null && <span> · source confidence {t.confidence}</span>}
      </div>
      {t.deprecated && (
        <p className="tech-why">
          <span className="k">Retired</span>
          Withdrawn from the pinned ATT&amp;CK corpus
          {t.revoked_by ? <> — replaced by <span className="data">{t.revoked_by}</span></> : null}. Shown so this finding keeps its reason.
        </p>
      )}
      {t.rationale && (
        <p className="tech-why"><span className="k">Why this mapping</span>{t.rationale}</p>
      )}
      {t.comments && (
        <p className="tech-why"><span className="k">Source note</span>{t.comments}</p>
      )}
    </div>
  );
}

function fmt(t?: string): string {
  return t ? new Date(t).toLocaleString() : "—";
}
