package store_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/effaaykhan/cvap/internal/store"
)

// ATT&CK technique reads (ADR-105).
//
// THESE TESTS SEED THEIR OWN CATALOGUE ROWS, and that is the point rather than a
// convenience. `attack_techniques` is a FEED: CI runs migrate-up and store-test
// against a fresh database and never runs `make knowledge-attack`, so the
// catalogue is empty there and every assertion about a returned technique would
// be vacuous. Seeding the three techniques the curated mappings name makes these
// tests assert the same thing whether or not a corpus has been ingested — the
// mistake this session already had to fix in internal/correlate, where seven
// tests passed only because the knowledge tables happened to be empty.
//
// ON CONFLICT DO NOTHING, and no assertion on a technique's NAME: on a developer
// box the real 16.1 corpus is loaded and already holds these ids with MITRE's
// own names, so the seed is a no-op there. Asserting the name would pass on CI
// and fail on the machine that has real data, which is the wrong way round.
func seedTechniqueCatalogue(t *testing.T) {
	t.Helper()
	url := os.Getenv("KNOWLEDGE_IMPORT_DATABASE_URL")
	if url == "" {
		t.Skip("KNOWLEDGE_IMPORT_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect as import role: %v", err)
	}
	defer pool.Close()
	for _, tq := range []struct{ id, name, tactic string }{
		{"T1040", "Network Sniffing", "credential-access"},
		{"T1557", "Adversary-in-the-Middle", "credential-access"},
		{"T1133", "External Remote Services", "initial-access"},
	} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO attack_techniques
			    (technique_id, name, tactics, url, is_subtechnique, deprecated, attack_version, last_fetched_at)
			VALUES ($1, $2, ARRAY[$3], 'https://attack.mitre.org/techniques/'||$1, false, false, '16.1', now())
			ON CONFLICT (technique_id) DO NOTHING`, tq.id, tq.name, tq.tactic); err != nil {
			t.Fatalf("seed technique %s: %v", tq.id, err)
		}
	}
}

// ruleNamed returns a builtin rule's id. The curated mappings are seeded by
// migration 0051 against these same names, so this is the join the production
// read performs, exercised from the test's side.
func ruleNamed(t *testing.T, db *store.DB, tenant store.TenantID, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx, `SELECT r.rule_id FROM rules r JOIN rule_packs p USING (rule_pack_id)
		                         WHERE r.name = $1 AND p.name = 'cvap-builtin'`, name).Scan(&id)
	}); err != nil {
		t.Fatalf("rule %q: %v", name, err)
	}
	return id
}

// findingOnRule writes one finding against a rule and returns its id.
func findingOnRule(t *testing.T, db *store.DB, tenant store.TenantID, ruleName, dedup string) uuid.UUID {
	t.Helper()
	ruleID := ruleNamed(t, db, tenant, ruleName)
	var id uuid.UUID
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		a, err := (store.Assets{}).Create(ctx, c, store.Asset{})
		if err != nil {
			return err
		}
		id, _, err = (store.Findings{}).Upsert(ctx, c, store.Finding{
			AssetID: a.ID, RuleID: ruleID, DedupKey: dedup, Locator: "23/tcp",
			Severity: "high", Confidence: 0.9, Summary: "seeded for technique tests",
		}, time.Now().UTC())
		return err
	}); err != nil {
		t.Fatalf("seed finding on %s: %v", ruleName, err)
	}
	return id
}

// A finding on a curated rule carries the curated techniques, labelled with the
// anchor that produced them and the reason a person gave.
func TestACuratedRuleCarriesItsTechniques(t *testing.T) {
	db := testDB(t)
	seedTechniqueCatalogue(t)
	tenant := newTenant(t, db, "attack-rule")
	id := findingOnRule(t, db, tenant, "plaintext-telnet", "tech-telnet-1")

	var got map[uuid.UUID][]store.Technique
	var cov store.TechniqueCoverage
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		got, cov, err = (store.Techniques{}).ForFindings(ctx, c, []uuid.UUID{id})
		return err
	}); err != nil {
		t.Fatal(err)
	}

	ts := got[id]
	if len(ts) != 2 {
		t.Fatalf("plaintext-telnet carried %d technique(s), want 2 (T1040 and T1557 per migration 0051): %+v", len(ts), ts)
	}
	seen := map[string]store.Technique{}
	for _, x := range ts {
		seen[x.ID] = x
	}
	for _, want := range []string{"T1040", "T1557"} {
		x, ok := seen[want]
		if !ok {
			t.Fatalf("technique %s missing; got %v", want, seen)
		}
		if x.Anchor != store.AnchorRule {
			t.Errorf("%s anchor = %q, want %q: a curated mapping must say it came from the rule, not the CVE", want, x.Anchor, store.AnchorRule)
		}
		if x.Source != "cvap-curated" {
			t.Errorf("%s source = %q, want cvap-curated: ADR-105 decision 1 requires every mapping to name who made the claim", want, x.Source)
		}
		// The rationale is what makes a curated judgement reviewable rather than
		// an unauditable assertion — the property ADR-105 rejected LLM-generated
		// mappings for lacking. A row that lost it is a row nobody can check.
		if x.Rationale == "" {
			t.Errorf("%s carries no rationale; a curated mapping that cannot say why it was made is not reviewable (ADR-105)", want)
		}
		if x.Confidence != nil {
			t.Errorf("%s carries confidence %v; no ingested source publishes one and ADR-105 forbids inventing it", want, *x.Confidence)
		}
	}
	if cov.Findings != 1 || cov.Mapped != 1 {
		t.Errorf("coverage = %+v, want 1 of 1 mapped", cov)
	}
}

// The other half of decision 4, and the half that is easy to get wrong: a rule
// with NO curated technique must come back absent, and coverage must say so.
// Absence has to be reported as "no mapping held", never rendered as a verdict.
func TestAnUnmappedRuleIsAbsentAndCoverageSaysSo(t *testing.T) {
	db := testDB(t)
	seedTechniqueCatalogue(t)
	tenant := newTenant(t, db, "attack-unmapped")

	// advisory-version-match is deliberately not curated (migration 0051 says
	// why): its findings carry a CVE, so the CVE anchor is the right route, and a
	// blanket technique would attach the same inference to every advisory
	// finding CVAP ever raises.
	unmapped := findingOnRule(t, db, tenant, "advisory-version-match", "tech-unmapped-1")
	mapped := findingOnRule(t, db, tenant, "plaintext-ftp", "tech-ftp-1")

	var got map[uuid.UUID][]store.Technique
	var cov store.TechniqueCoverage
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		got, cov, err = (store.Techniques{}).ForFindings(ctx, c, []uuid.UUID{unmapped, mapped})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(got[unmapped]) != 0 {
		t.Errorf("advisory-version-match carried %d technique(s), want none: it is deliberately uncurated", len(got[unmapped]))
	}
	if len(got[mapped]) == 0 {
		t.Error("plaintext-ftp carried no technique; the curated mapping should have reached it")
	}
	if cov.Findings != 2 || cov.Mapped != 1 {
		t.Errorf("coverage = %+v, want 2 findings with 1 mapped — the number that keeps 'unmapped' from reading as 'nothing applies'", cov)
	}
}

// One tenant's findings must not pick up another's. The mapping tables are
// global and untenanted by design (ADR-105 decision 1), which is exactly the
// shape that makes a missing tenant predicate invisible in review: the join
// would still return plausible techniques, just for the wrong finding.
func TestTechniquesDoNotCrossTenants(t *testing.T) {
	db := testDB(t)
	seedTechniqueCatalogue(t)
	a := newTenant(t, db, "attack-tenant-a")
	b := newTenant(t, db, "attack-tenant-b")
	idA := findingOnRule(t, db, a, "plaintext-telnet", "tech-cross-a")

	var got map[uuid.UUID][]store.Technique
	var cov store.TechniqueCoverage
	if err := db.Read(context.Background(), b, func(ctx context.Context, c *store.Conn) error {
		var err error
		got, cov, err = (store.Techniques{}).ForFindings(ctx, c, []uuid.UUID{idA})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("tenant B read %d technique set(s) for tenant A's finding: %v", len(got), got)
	}
	if cov.Mapped != 0 {
		t.Errorf("coverage.Mapped = %d for another tenant's finding, want 0", cov.Mapped)
	}
}

// An empty id list must not produce a query, and must not report coverage over
// nothing as though something were mapped.
func TestNoFindingsIsNotCoverage(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "attack-empty")
	var cov store.TechniqueCoverage
	var got map[uuid.UUID][]store.Technique
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		got, cov, err = (store.Techniques{}).ForFindings(ctx, c, nil)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Error("ForFindings returned a nil map for an empty batch; callers index it directly")
	}
	if cov.Findings != 0 || cov.Mapped != 0 {
		t.Errorf("coverage = %+v over an empty batch, want zero/zero", cov)
	}
}

// CatalogueStatus exists to separate "this finding has no mapping" from "nothing
// has been ingested, so NOTHING can have one". Without that distinction,
// forgetting `make knowledge-attack` reads exactly like complete coverage of an
// estate with no techniques.
func TestCatalogueStatusReportsWhatIsLoaded(t *testing.T) {
	db := testDB(t)
	seedTechniqueCatalogue(t)
	tenant := newTenant(t, db, "attack-status")

	var st store.CatalogueStatus
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		st, err = (store.Techniques{}).CatalogueStatus(ctx, c)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if st.Techniques < 3 {
		t.Errorf("catalogue holds %d technique(s), want at least the 3 seeded here", st.Techniques)
	}
	// Migration 0051 curates 16 rows over 11 of the 14 builtin rules. The three
	// left alone are a decision, not an oversight, and the numbers are asserted
	// so that curating a twelfth silently is not possible.
	if st.CuratedRules != 11 {
		t.Errorf("curated rules = %d, want 11 (migration 0051); if a rule was added or curated, update both", st.CuratedRules)
	}
	if st.TotalRules < st.CuratedRules {
		t.Errorf("curated rules (%d) exceeds total rules (%d)", st.CuratedRules, st.TotalRules)
	}
	if st.AttackVersion == "" {
		t.Error("catalogue reports no ATT&CK version; a corpus with no version cannot be pinned or diffed (ADR-105)")
	}
}
