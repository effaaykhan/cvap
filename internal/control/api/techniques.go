package api

import (
	"github.com/effaaykhan/cvap/internal/store"
)

// MITRE ATT&CK on the API surface (ADR-105).
//
// ADR-105 decision 3 puts the WORDING in the contract, not in the console: "the
// API field says what it is and what produced it; the console never presents a
// technique as something observed". So the labelling lives here, where every
// client gets it, rather than in one screen's copy where the next client would
// have to reinvent it — the same reason a seen-only port reads "open,
// unidentified" from the API rather than from the UI (ADR-103).

// TechniqueResponse is one ATT&CK technique attached to a finding.
type TechniqueResponse struct {
	ID      string   `json:"id" doc:"MITRE ATT&CK technique id, e.g. T1040 or T1190.001."`
	Name    string   `json:"name"`
	Tactics []string `json:"tactics" doc:"ATT&CK tactic shortnames this technique serves, e.g. credential-access."`
	URL     string   `json:"url,omitempty" doc:"The MITRE page for this technique."`

	// Inference is a constant, and it is a field rather than documentation
	// because a client that renders whatever the API sends will then say the
	// right thing without having read this ADR.
	Inference string `json:"inference" doc:"Always \"inferred\". CVAP does not exploit anything (non-negotiable #9) and has NOT observed this technique being used — this is a judgement about what the weakness would enable."`

	Anchor string `json:"anchor" doc:"How this technique reached the finding: \"rule\" (curated for this detection rule) or \"cve\" (a published dataset's mapping for the CVE)."`
	Source string `json:"source" doc:"Who made the claim, e.g. cvap-curated or ctid-mappings-explorer."`

	MappingType string   `json:"mapping_type,omitempty" doc:"The source's OWN qualifier on a CVE mapping (exploitation_technique | primary_impact | secondary_impact). Absent on the rule anchor."`
	Rationale   string   `json:"rationale,omitempty" doc:"The curator's reason, on the rule anchor only."`
	Comments    string   `json:"comments,omitempty" doc:"The source's own note, on the CVE anchor only."`
	Confidence  *float64 `json:"confidence,omitempty" doc:"The SOURCE's confidence, absent when it publishes none — which is currently every ingested source. Never a number CVAP invents (ADR-105)."`

	// Deprecated techniques are RETURNED, never filtered: a finding that cited
	// one must still explain itself after the technique leaves the corpus
	// (ADR-105's retirement rule).
	Deprecated bool   `json:"deprecated,omitempty" doc:"Retired from the pinned ATT&CK corpus. Still shown so an older finding keeps its reason."`
	RevokedBy  string `json:"revoked_by,omitempty" doc:"The technique that replaced this one."`
}

// TechniqueCoverageResponse states what fraction of the returned findings carry
// any technique.
//
// ADR-105 decision 4 requires this: silence would say "no technique applies",
// which is a stronger and different claim from "we have no mapping". A client
// showing techniques without showing coverage turns a partial feed into an
// apparent statement of fact about every unmapped finding.
type TechniqueCoverageResponse struct {
	Findings  int    `json:"findings" doc:"Findings in this response."`
	Mapped    int    `json:"mapped" doc:"Of those, how many carry at least one ATT&CK technique."`
	Statement string `json:"statement" doc:"Plain-language coverage, for a client that would otherwise show nothing and imply completeness."`
}

func techniqueResponses(ts []store.Technique) []TechniqueResponse {
	out := make([]TechniqueResponse, 0, len(ts))
	for _, t := range ts {
		out = append(out, TechniqueResponse{
			ID: t.ID, Name: t.Name, Tactics: t.Tactics, URL: t.URL,
			Inference: "inferred",
			Anchor:    t.Anchor, Source: t.Source,
			MappingType: t.MappingType, Rationale: t.Rationale, Comments: t.Comments,
			Confidence: t.Confidence,
			Deprecated: t.Deprecated, RevokedBy: t.RevokedBy,
		})
	}
	return out
}

// coverageStatement spells out the three states a reader must be able to tell
// apart. The middle one is the reason this function exists: an installation that
// has never run `make knowledge-attack` looks, from a finding, exactly like one
// where nothing happened to match — and those mean completely different things.
func coverageStatement(cov store.TechniqueCoverage, catalogueLoaded bool) string {
	switch {
	case cov.Findings == 0:
		return "No findings to map."
	case !catalogueLoaded:
		return "No ATT&CK catalogue has been ingested, so no finding can carry a technique. Run `make knowledge-attack`. This is not evidence that no technique applies."
	case cov.Mapped == 0:
		return "None of these findings carries an ATT&CK technique. That means CVAP holds no mapping for them, NOT that no technique applies."
	case cov.Mapped < cov.Findings:
		return "Some of these findings carry no ATT&CK technique. Unmapped means CVAP holds no mapping, NOT that no technique applies."
	default:
		return "Every finding here carries at least one ATT&CK technique."
	}
}

// AttackCoverageResponse is the ATT&CK half of the knowledge surface.
//
// ADR-105 decision 4 has two halves. The per-finding half is TechniqueCoverage
// above. This is the other one: "the surface reports what fraction is mapped".
// Without it the mapping layer has no place to answer the question an operator
// actually asks on seeing an unmapped finding — is this estate genuinely
// untouched by ATT&CK, or did nobody run the importer? Those look identical from
// a finding and are completely different facts.
//
// The numbers are deliberately split into what the DATASET holds and what THIS
// installation can use. A surface reporting only "1,183 mappings ingested" would
// read as coverage; the number that matters is how many of the CVEs this
// installation actually has are among them, and on a USN-only advisory set that
// is currently zero.
type AttackCoverageResponse struct {
	CatalogueVersion string `json:"catalogue_version,omitempty" doc:"The pinned ATT&CK corpus version, e.g. 16.1. Absent when no catalogue has been ingested."`
	Techniques       int    `json:"techniques" doc:"Techniques in the catalogue."`
	Deprecated       int    `json:"deprecated" doc:"Of those, retired from the pinned corpus. Retained, never deleted, so an older finding keeps its reason."`

	CVEMappings int `json:"cve_mappings" doc:"Rows in the published CVE->technique dataset."`
	MappedCVEs  int `json:"mapped_cves" doc:"Distinct CVEs that dataset covers, regardless of whether this installation holds them."`

	LocalCVEs       int `json:"local_cves" doc:"CVE definitions this installation has ingested."`
	LocalMappedCVEs int `json:"local_mapped_cves" doc:"Of those, how many carry an ATT&CK mapping. THIS is the number that decides whether advisory findings can show a technique."`

	CuratedRules int `json:"curated_rules" doc:"Detection rules carrying a curated technique."`
	TotalRules   int `json:"total_rules" doc:"Detection rules in total. The difference is rules whose findings read \"unmapped\"."`

	// Statement exists because every number above can be read as a verdict by
	// someone who does not know how this feed is built. It says which of the
	// three states the installation is in, in words.
	Statement string `json:"statement"`
}

// attackCoverageStatement names the state rather than leaving it to arithmetic.
//
// The middle case is the one worth the code: a published dataset that covers
// CISA KEV cannot intersect a USN-only advisory set, because one describes
// commercial and appliance software and the other describes Ubuntu archive
// packages. An operator reading "0 mapped" with no explanation concludes the
// feature is broken. It is not — it is ADR-105's predicted coverage problem,
// and saying so is the difference between a measured result and an apparent
// failure.
func attackCoverageStatement(st store.CatalogueStatus) string {
	switch {
	case st.Techniques == 0:
		return "No ATT&CK catalogue has been ingested, so no finding anywhere can carry a technique. Run `make knowledge-attack`. Until then an unmapped finding says nothing about whether a technique applies."
	case st.CVEMappings == 0:
		return "The technique catalogue is loaded but no CVE mappings are. Advisory findings will read unmapped; rule findings still carry their curated techniques. Run `make knowledge-attack-mappings`."
	case st.LocalMappedCVEs == 0 && st.CuratedRules > 0:
		return "No ingested CVE carries a mapping: the published dataset covers CISA KEV, which is commercial and appliance software, and this installation's CVEs come from Ubuntu advisories. The two sets describe different software, so the overlap is genuinely empty rather than missing. Rule-based findings still carry curated techniques."
	case st.LocalMappedCVEs == 0:
		return "No ingested CVE carries a mapping, and no rule carries a curated technique, so nothing will show a technique today. This is a coverage fact, not a verdict that no technique applies."
	default:
		return "Techniques are available from both anchors: curated rule mappings and the published CVE dataset."
	}
}

func attackCoverageResponse(st store.CatalogueStatus) AttackCoverageResponse {
	return AttackCoverageResponse{
		CatalogueVersion: st.AttackVersion,
		Techniques:       st.Techniques,
		Deprecated:       st.Deprecated,
		CVEMappings:      st.CVEMappings,
		MappedCVEs:       st.MappedCVEs,
		LocalCVEs:        st.LocalCVEs,
		LocalMappedCVEs:  st.LocalMappedCVEs,
		CuratedRules:     st.CuratedRules,
		TotalRules:       st.TotalRules,
		Statement:        attackCoverageStatement(st),
	}
}
