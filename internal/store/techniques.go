package store

import (
	"context"

	"github.com/google/uuid"
)

// MITRE ATT&CK reads (ADR-105). Global knowledge tables read from inside a
// tenant-scoped transaction, the same way the finding path reads `rules` and
// `kev` — a global table read from within a tenant Read is not an unscoped read
// of tenant data (ADR-030).
//
// WHAT THESE ROWS ARE, AND WHY THE TYPE SAYS SO. A technique here is an
// INFERENCE about a weakness — someone's reasoning about what an adversary could
// do — never a record of anything observed. CVAP does not exploit anything
// (non-negotiable #9), so it cannot report how something WAS exploited. ADR-105
// decision 3 makes that labelling part of the contract rather than a UI
// preference, which is why Source and Anchor are on the struct and not optional:
// a technique that cannot say where it came from must not reach a screen.
type Techniques struct{}

// Technique anchors (ADR-105 decision 2). A finding carries a rule_id always and
// a vuln_def_id optionally (non-negotiable #4), so a technique reaches it by one
// of exactly two routes, and which route it took changes how much weight it
// carries: AnchorRule is a judgement a person made about this specific rule,
// AnchorCVE is a third party's judgement about the CVE.
const (
	AnchorRule = "rule"
	AnchorCVE  = "cve"
)

// Technique is one ATT&CK technique as it reaches a finding.
type Technique struct {
	ID      string // T1190, or T1190.001
	Name    string
	Tactics []string
	URL     string

	// Deprecated is true for a technique retired from the pinned corpus. It is
	// still returned, never filtered: a finding that cited it must still be able
	// to explain itself (ADR-105's retirement rule), and hiding it would make an
	// old finding silently lose its reason.
	Deprecated bool
	RevokedBy  string

	// Provenance. Anchor is how it reached the finding (AnchorRule/AnchorCVE);
	// Source names who made the claim.
	Anchor string
	Source string

	// MappingType is the SOURCE's own qualifier on a CVE mapping
	// ("exploitation_technique", "primary_impact", "secondary_impact"). Empty on
	// the rule anchor.
	MappingType string

	// Rationale is the curator's reason, on the rule anchor only. Empty for CVE
	// mappings, which carry the source's Comments instead.
	Rationale string
	Comments  string

	// Confidence is the SOURCE's own confidence, nil when it publishes none —
	// which is the case for every source currently ingested. Never a number this
	// project invents (ADR-105 decision 1).
	Confidence *float64
}

// TechniqueCoverage is what fraction of a set of findings carries any technique.
// ADR-105 decision 4: coverage is STATED, never implied by absence, because
// silence would say "no technique applies" — a stronger and different claim from
// "we have no mapping".
type TechniqueCoverage struct {
	Findings int // findings considered
	Mapped   int // of those, how many carry at least one technique
}

const techniqueSelectSQL = `
	SELECT f.finding_id, at.technique_id, at.name, at.tactics, coalesce(at.url, ''),
	       at.deprecated, coalesce(at.revoked_by, ''),
	       '` + AnchorRule + `' AS anchor, rt.source, '' AS mapping_type,
	       rt.rationale, '' AS comments, NULL::numeric AS confidence
	  FROM findings f
	  JOIN rule_techniques rt   ON rt.rule_id = f.rule_id
	  JOIN attack_techniques at ON at.technique_id = rt.technique_id
	 WHERE f.tenant_id = $1 AND f.finding_id = ANY($2)
	UNION ALL
	SELECT f.finding_id, at.technique_id, at.name, at.tactics, coalesce(at.url, ''),
	       at.deprecated, coalesce(at.revoked_by, ''),
	       '` + AnchorCVE + `' AS anchor, ct.source, ct.mapping_type,
	       '' AS rationale, coalesce(ct.comments, ''), ct.source_confidence
	  FROM findings f
	  JOIN vulnerability_defs vd ON vd.vuln_def_id = f.vuln_def_id
	  JOIN cve_techniques ct     ON ct.cve_id = vd.cve_id
	  JOIN attack_techniques at  ON at.technique_id = ct.technique_id
	 WHERE f.tenant_id = $1 AND f.finding_id = ANY($2)
	 ORDER BY 1, 8, 2`

// ForFindings returns the techniques for a batch of findings, keyed by finding
// id, plus the coverage over that batch.
//
// Batched rather than per-finding on purpose: the finding list is the screen this
// feeds, and a per-row lookup there would be one query per listed finding inside
// a transaction that already carries a time budget (ADR-101). A finding with no
// techniques is simply absent from the map, and the caller renders "unmapped" —
// the map's zero value and the honest answer are the same thing.
//
// The rule anchor is ordered first (AnchorRule < AnchorCVE lexically), so a
// curated judgement about this rule leads over a third party's about the CVE.
func (Techniques) ForFindings(ctx context.Context, c *Conn, ids []uuid.UUID) (map[uuid.UUID][]Technique, TechniqueCoverage, error) {
	cov := TechniqueCoverage{Findings: len(ids)}
	if len(ids) == 0 {
		return map[uuid.UUID][]Technique{}, cov, nil
	}
	rows, err := c.Query(ctx, techniqueSelectSQL, c.Tenant().UUID(), ids)
	if err != nil {
		return nil, cov, mapError(err)
	}
	defer rows.Close()

	out := make(map[uuid.UUID][]Technique)
	for rows.Next() {
		var id uuid.UUID
		var t Technique
		if err := rows.Scan(&id, &t.ID, &t.Name, &t.Tactics, &t.URL, &t.Deprecated,
			&t.RevokedBy, &t.Anchor, &t.Source, &t.MappingType, &t.Rationale,
			&t.Comments, &t.Confidence); err != nil {
			return nil, cov, mapError(err)
		}
		out[id] = append(out[id], t)
	}
	if err := rows.Err(); err != nil {
		return nil, cov, mapError(err)
	}
	cov.Mapped = len(out)
	return out, cov, nil
}

// CatalogueStatus reports what the technique catalogue holds. It exists so the
// knowledge surface can distinguish "this finding has no mapping" from "no
// catalogue has been ingested, so NOTHING can have a mapping" — two states that
// look identical on a finding and mean entirely different things. Without it,
// forgetting `make knowledge-attack` reads exactly like full coverage of zero.
type CatalogueStatus struct {
	Techniques      int    // rows in attack_techniques
	Deprecated      int    // of those, retired from the pinned corpus
	CVEMappings     int    // rows in cve_techniques
	MappedCVEs      int    // distinct CVEs the mapping feed covers
	LocalMappedCVEs int    // of THIS installation's vulnerability_defs, how many are mapped
	LocalCVEs       int    // vulnerability_defs total
	CuratedRules    int    // rules carrying a curated technique
	TotalRules      int    // rules in total
	AttackVersion   string // the pinned corpus version, "" when nothing is ingested
}

func (Techniques) CatalogueStatus(ctx context.Context, c *Conn) (CatalogueStatus, error) {
	const q = `
		SELECT (SELECT count(*) FROM attack_techniques),
		       (SELECT count(*) FROM attack_techniques WHERE deprecated),
		       (SELECT count(*) FROM cve_techniques),
		       (SELECT count(DISTINCT cve_id) FROM cve_techniques),
		       (SELECT count(DISTINCT vd.cve_id) FROM vulnerability_defs vd
		          JOIN cve_techniques ct ON ct.cve_id = vd.cve_id),
		       (SELECT count(*) FROM vulnerability_defs),
		       (SELECT count(DISTINCT rule_id) FROM rule_techniques),
		       (SELECT count(*) FROM rules),
		       coalesce((SELECT max(attack_version) FROM attack_techniques), '')`
	var s CatalogueStatus
	err := c.QueryRow(ctx, q).Scan(&s.Techniques, &s.Deprecated, &s.CVEMappings,
		&s.MappedCVEs, &s.LocalMappedCVEs, &s.LocalCVEs, &s.CuratedRules,
		&s.TotalRules, &s.AttackVersion)
	if err != nil {
		return s, mapError(err)
	}
	return s, nil
}
