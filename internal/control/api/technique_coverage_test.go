package api

import (
	"strings"
	"testing"

	"github.com/effaaykhan/cvap/internal/store"
)

// These guards are checked by `make mutate`, because a test asserting that a
// LABEL is present is exactly the kind that keeps passing after the label stops
// meaning anything. Each mutation restores a plausible earlier version of the
// code -- the shape somebody would write who had not read ADR-105.
//
// ONE mutate:test for the whole file, listing every case's test — mutate.py keeps
// only the LAST mutate:test it sees and applies it to every case, so a per-case
// line does not scope anything. The first version of this block had three, and
// two of its three mutations SURVIVED: all of them ran only the deprecated-
// technique test, which says nothing about the inference label or the coverage
// statement. `internal/engines/fingerprint/payload_test.go` documents this trap
// and it still got walked into, which is the argument for running the gate
// rather than reasoning about it.
//
// mutate:subject internal/control/api/techniques.go
// mutate:test    ./internal/control/api/ -run TestCoverageStatementSeparates|TestEveryCoverageStateIsStated|TestEveryTechniqueIsLabelled|TestADeprecatedTechniqueIsStill|TestAttackCoverageStatementSeparates|TestAttackCoverageReportsLocal
//
// mutate:case    an empty catalogue is reported the same way as an unmapped finding set
// mutate:old     case !catalogueLoaded:
// mutate:new     case false:
//
// mutate:case    the inference label is dropped from the API contract
// mutate:old     Inference: "inferred",
// mutate:new     Inference: "",
//
// mutate:case    deprecated techniques are filtered out, so an old finding loses its reason
// mutate:old     for _, t := range ts {
// mutate:new     for _, t := range ts { if t.Deprecated { continue }
//
// mutate:case    an empty catalogue and an empty mapping set are reported the same way
// mutate:old     case st.CVEMappings == 0:
// mutate:new     case false:
//
// mutate:case    the surface reports the dataset's coverage as this installation's
// mutate:old     LocalMappedCVEs:  st.LocalMappedCVEs,
// mutate:new     LocalMappedCVEs:  st.MappedCVEs,

// ADR-105 decision 4: coverage is STATED, never implied by absence, because
// silence says "no technique applies" — a stronger and different claim from "we
// have no mapping".
//
// The case that matters most is the one a reader cannot see from a finding: an
// installation that never ran `make knowledge-attack` looks EXACTLY like one
// where nothing happened to match. Both show no techniques. One means "we hold
// no mapping for this"; the other means "nothing can be mapped at all, and the
// operator should go and fix that". A statement that cannot separate them lets a
// forgotten ingest read as a clean result.
func TestCoverageStatementSeparatesNoMappingFromNoCatalogue(t *testing.T) {
	noCatalogue := coverageStatement(store.TechniqueCoverage{Findings: 5, Mapped: 0}, false)
	noMapping := coverageStatement(store.TechniqueCoverage{Findings: 5, Mapped: 0}, true)

	if noCatalogue == noMapping {
		t.Fatalf("an empty catalogue and an unmapped finding set produce the same statement (%q). "+
			"They are the two states a reader most needs to tell apart: one is a missing ingest, "+
			"the other is a measured result.", noCatalogue)
	}
	if !strings.Contains(strings.ToLower(noCatalogue), "knowledge-attack") {
		t.Errorf("the no-catalogue statement does not say how to fix it: %q", noCatalogue)
	}
	// Both must refuse the stronger reading. This is the sentence that stops an
	// operator concluding a host is technique-free.
	for name, s := range map[string]string{"no catalogue": noCatalogue, "no mapping": noMapping} {
		if !strings.Contains(strings.ToLower(s), "not") {
			t.Errorf("%s statement does not disclaim the stronger reading: %q", name, s)
		}
	}
}

// Every reachable state produces a distinct, non-empty statement. A statement
// that silently falls through to "" would render as nothing, which is precisely
// the silence decision 4 forbids.
func TestEveryCoverageStateIsStated(t *testing.T) {
	cases := []struct {
		name      string
		cov       store.TechniqueCoverage
		catalogue bool
	}{
		{"no findings", store.TechniqueCoverage{}, true},
		{"no catalogue", store.TechniqueCoverage{Findings: 3}, false},
		{"none mapped", store.TechniqueCoverage{Findings: 3}, true},
		{"some mapped", store.TechniqueCoverage{Findings: 3, Mapped: 1}, true},
		{"all mapped", store.TechniqueCoverage{Findings: 3, Mapped: 3}, true},
	}
	seen := map[string]string{}
	for _, c := range cases {
		s := coverageStatement(c.cov, c.catalogue)
		if strings.TrimSpace(s) == "" {
			t.Errorf("%s produced an empty statement; empty renders as silence, which is the claim decision 4 forbids", c.name)
		}
		if prev, dup := seen[s]; dup {
			t.Errorf("%s and %s produce the same statement %q; a state that cannot be distinguished is not stated", c.name, prev, s)
		}
		seen[s] = c.name
	}
}

// Every technique that reaches the API says it is an inference, whatever anchor
// produced it. ADR-105 decision 3 puts this in the CONTRACT rather than in the
// console: a client that renders what the API sends must say the right thing
// without having read the ADR.
func TestEveryTechniqueIsLabelledAnInference(t *testing.T) {
	in := []store.Technique{
		{ID: "T1040", Name: "Network Sniffing", Anchor: store.AnchorRule, Source: "cvap-curated", Rationale: "why"},
		{ID: "T1190", Name: "Exploit Public-Facing Application", Anchor: store.AnchorCVE, Source: "ctid-mappings-explorer", MappingType: "exploitation_technique"},
	}
	out := techniqueResponses(in)
	if len(out) != len(in) {
		t.Fatalf("got %d responses for %d techniques", len(out), len(in))
	}
	for _, r := range out {
		if r.Inference != "inferred" {
			t.Errorf("%s inference = %q, want \"inferred\": CVAP has not observed any technique being used (non-negotiable #9)", r.ID, r.Inference)
		}
		if r.Source == "" {
			t.Errorf("%s reached the API with no source; a claim that cannot say who made it must not be renderable (ADR-105 decision 1)", r.ID)
		}
		if r.Anchor == "" {
			t.Errorf("%s reached the API with no anchor; a curated judgement and a third party's CVE mapping carry different weight", r.ID)
		}
		if r.Confidence != nil {
			t.Errorf("%s carries an invented confidence %v; no ingested source publishes one", r.ID, *r.Confidence)
		}
	}
}

// A deprecated technique must still reach the client. ADR-105's retirement rule:
// a finding that cited T1234 last quarter must still explain itself, so filtering
// retired techniques would silently strip an old finding's only reason.
func TestADeprecatedTechniqueIsStillReturned(t *testing.T) {
	out := techniqueResponses([]store.Technique{
		{ID: "T1234", Name: "Retired", Anchor: store.AnchorCVE, Source: "s", Deprecated: true, RevokedBy: "T5678"},
	})
	if len(out) != 1 {
		t.Fatalf("a deprecated technique was dropped; an older finding would lose its reason (ADR-105)")
	}
	if !out[0].Deprecated || out[0].RevokedBy != "T5678" {
		t.Errorf("deprecation not carried through: %+v", out[0])
	}
}

// The knowledge surface's ATT&CK half (ADR-105 decision 4, second sentence:
// "the surface reports what fraction is mapped").
//
// The states it must separate are not degrees of the same thing. "Nobody ran the
// importer", "the catalogue is in but the mappings are not", and "both are in
// and this estate genuinely does not intersect the dataset" are three different
// facts with three different actions, and all three show zero techniques on a
// finding. A surface that collapses any two of them tells an operator to go and
// fix something that is not broken, or not to fix something that is.
func TestAttackCoverageStatementSeparatesEveryState(t *testing.T) {
	cases := []struct {
		name string
		st   store.CatalogueStatus
		must string // a word the statement must contain to be actionable
	}{
		{"nothing ingested", store.CatalogueStatus{}, "knowledge-attack"},
		{"catalogue only", store.CatalogueStatus{Techniques: 799, LocalCVEs: 6028}, "knowledge-attack-mappings"},
		{"no overlap, rules curated", store.CatalogueStatus{
			Techniques: 799, CVEMappings: 1183, MappedCVEs: 419,
			LocalCVEs: 6028, LocalMappedCVEs: 0, CuratedRules: 11, TotalRules: 14}, "Ubuntu"},
		{"no overlap, nothing curated", store.CatalogueStatus{
			Techniques: 799, CVEMappings: 1183, LocalCVEs: 6028, TotalRules: 14}, "coverage fact"},
		{"both anchors live", store.CatalogueStatus{
			Techniques: 799, CVEMappings: 1183, LocalCVEs: 6028, LocalMappedCVEs: 12,
			CuratedRules: 11, TotalRules: 14}, "anchors"},
	}
	seen := map[string]string{}
	for _, c := range cases {
		got := attackCoverageStatement(c.st)
		if strings.TrimSpace(got) == "" {
			t.Errorf("%s produced an empty statement; silence is the claim decision 4 forbids", c.name)
			continue
		}
		if prev, dup := seen[got]; dup {
			t.Errorf("%s and %s produce the SAME statement %q — they need different actions from the operator", c.name, prev, got)
		}
		seen[got] = c.name
		if !strings.Contains(got, c.must) {
			t.Errorf("%s statement does not mention %q, so it does not say what to do: %q", c.name, c.must, got)
		}
	}
}

// The response must report what THIS installation can use, not just what the
// dataset holds. "1,183 mappings ingested" beside "0 of your CVEs are mapped"
// are both true and only the second one answers the question; a surface carrying
// only the first reads as coverage it does not have.
func TestAttackCoverageReportsLocalNotJustDataset(t *testing.T) {
	r := attackCoverageResponse(store.CatalogueStatus{
		Techniques: 799, Deprecated: 143, CVEMappings: 1183, MappedCVEs: 419,
		LocalCVEs: 6028, LocalMappedCVEs: 0, CuratedRules: 11, TotalRules: 14,
		AttackVersion: "16.1",
	})
	if r.MappedCVEs == r.LocalMappedCVEs {
		t.Fatal("the dataset's coverage and this installation's coverage are reported as the same number; they are the two halves that must not be confused")
	}
	if r.LocalMappedCVEs != 0 || r.LocalCVEs != 6028 {
		t.Errorf("local coverage = %d of %d, want 0 of 6028", r.LocalMappedCVEs, r.LocalCVEs)
	}
	if r.CatalogueVersion != "16.1" {
		t.Errorf("catalogue version = %q, want 16.1: a corpus with no version cannot be pinned or diffed", r.CatalogueVersion)
	}
	if r.Deprecated == 0 {
		t.Error("deprecated count not reported; retired techniques are retained and an operator should see how many")
	}
	if strings.TrimSpace(r.Statement) == "" {
		t.Error("no statement on the coverage response")
	}
}
