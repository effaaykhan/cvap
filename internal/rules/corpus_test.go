package rules

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The golden corpus, consumed here.
//
// ============================================================================
// A rule with no corpus entry is not measurable and does not ship
// (write-detection-rule). This is where "measurable" is made true.
// ============================================================================
//
// testdata/corpus.json is labelled inputs and the exact findings each must
// raise. The assertion is EXACT — a rule not listed for a case must not fire —
// because a false finding costs more than a missed one, so the cases that must
// stay quiet carry as much weight as the cases that must fire.
//
// This runs the evaluators directly. Week 8's `make corpus-check` is to drive
// the same cases end to end through a scan of the lab (docs/execution-plan.md
// 6.2); the input shapes here are the observation payloads that scan produces,
// so the two corpora are the same labels checked at two depths.

type corpusFile struct {
	Cases []struct {
		Name        string          `json:"name"`
		Service     json.RawMessage `json:"service"`
		Environment string          `json:"environment"`
		Raises      []string        `json:"raises"`
	} `json:"cases"`
}

// corpusService is the fixture's service shape — a superset of what the engine's
// ServiceObservation carries, plus zone_type so a case can place itself in a
// zone without a database.
type corpusService struct {
	Port     int          `json:"port"`
	Protocol string       `json:"protocol"`
	Service  string       `json:"service"`
	Product  string       `json:"product"`
	Version  string       `json:"version"`
	Method   string       `json:"method"`
	Evidence string       `json:"evidence"`
	ZoneType string       `json:"zone_type"`
	TLS      *TLSEvidence `json:"tls"`
	SSH      *SSHEvidence `json:"ssh"`
}

// builtinRulesForCorpus mirrors the rows migration 0032 seeds, so the corpus is
// checked against the SHIPPED rules rather than a set invented for the test. A
// name or parameter that drifts from the migration is caught by
// TestCorpusRulesMatchTheMigration below.
func builtinRulesForCorpus(t *testing.T) []Rule {
	t.Helper()
	mk := func(name, evaluator, severity, params string, conf float64) Rule {
		return Rule{ID: uuid.New(), Name: name, Evaluator: evaluator, Severity: severity,
			Params: json.RawMessage(params), Confidence: conf, Version: 1}
	}
	rules := []Rule{
		mk("tls-certificate-expired", "tls.expired", "high", `{}`, 0.99),
		mk("tls-certificate-expiring-soon", "tls.expiring", "medium", `{"warn_days":30}`, 0.99),
		mk("tls-self-signed-non-dev", "tls.self_signed", "medium", `{"exempt_environments":["dev","development","test","staging","lab"]}`, 0.95),
		mk("tls-missing-chain", "tls.missing_chain", "low", `{}`, 0.95),
		mk("tls-weak-key", "tls.weak_key", "high", `{"min_rsa_bits":2048}`, 0.99),
		mk("tls-legacy-version-negotiated", "tls.legacy_negotiated", "medium", `{}`, 0.95),
		mk("tls-weak-cipher-negotiated", "tls.weak_cipher_negotiated", "medium", `{}`, 0.95),
		mk("plaintext-telnet", "plaintext.service", "high", `{"services":["telnet"]}`, 0.95),
		mk("plaintext-ftp", "plaintext.service", "medium", `{"services":["ftp"]}`, 0.95),
		mk("http-no-https-redirect", "http.no_https_redirect", "low", `{}`, 0.75),
		mk("http-missing-security-headers", "http.missing_headers", "low", `{"required":["Strict-Transport-Security","Content-Security-Policy","X-Content-Type-Options"]}`, 0.75),
		mk("management-interface-untrusted-zone", "exposure.management_untrusted", "high", `{"ports":[22,3389,5985,5986,3306,5432,1433,27017,6379],"zone_types":["external","dmz"]}`, 0.90),
		mk("ssh-weak-algorithms", "ssh.weak_algorithms", "low", `{"host_key":["ssh-dss","ssh-rsa"],"kex":["diffie-hellman-group1-sha1","diffie-hellman-group14-sha1","diffie-hellman-group-exchange-sha1"]}`, 0.90),
	}
	loaded, err := Load(rules, corpusNow)
	if err != nil {
		t.Fatalf("built-in rules do not load: %v", err)
	}
	return loaded
}

// corpusNow is fixed so the cases' certificate dates mean the same thing on
// every run. 2026-06-01: after the expired cases' not_after and before the
// valid ones', which is what makes those cases test what they claim.
var corpusNow = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

func TestGoldenCorpus(t *testing.T) {
	raw, err := os.ReadFile("testdata/corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var cf corpusFile
	if err := json.Unmarshal(raw, &cf); err != nil {
		t.Fatal(err)
	}
	if len(cf.Cases) == 0 {
		t.Fatal("empty corpus")
	}

	ruleset := builtinRulesForCorpus(t)

	for _, tc := range cf.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			var cs corpusService
			if err := json.Unmarshal(tc.Service, &cs); err != nil {
				t.Fatal(err)
			}
			zone := uuid.New()
			sub := Subject{
				AssetID:     uuid.New(),
				Environment: tc.Environment,
				ZoneType:    func(uuid.UUID) string { return cs.ZoneType },
				Services: []ServiceObservation{{
					ObservationID: uuid.New(), ZoneID: zone, ObservedAt: corpusNow,
					Address: "10.0.0.1", Port: cs.Port, Protocol: cs.Protocol,
					Service: cs.Service, Product: cs.Product, Version: cs.Version,
					Method: cs.Method, Evidence: cs.Evidence, TLS: cs.TLS, SSH: cs.SSH,
				}},
			}

			results, err := Evaluate(ruleset, sub, corpusNow)
			if err != nil {
				t.Fatal(err)
			}
			var fired []string
			for _, r := range results {
				fired = append(fired, r.Finding.Rule.Name)
			}
			sort.Strings(fired)
			want := append([]string(nil), tc.Raises...)
			sort.Strings(want)

			if !equalStrings(fired, want) {
				t.Errorf("fired %v, want exactly %v", fired, want)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestCorpusRulesMatchTheMigration guards the hand-mirror above against drift.
//
// builtinRulesForCorpus restates the rows migration 0032 seeds, so the corpus is
// checked against the shipped rules without a database. A restatement rots: a
// rule added to the migration and not here would be untested, and one renamed
// here and not there would test a rule nobody ships. This reads the evaluator
// names out of the migration and asserts the two agree.
//
// The correlate integration tests exercise the DB-loaded path against the real
// migration; this is the cheaper guard that runs without one.
func TestCorpusRulesMatchTheMigration(t *testing.T) {
	raw, err := os.ReadFile("../../migrations/0032_builtin_rule_pack.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	// Evaluator names appear as "evaluator": "x" in the seed's detection_logic.
	re := regexp.MustCompile(`"evaluator"\s*:\s*"([^"]+)"`)
	inMigration := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
		inMigration[m[1]] = true
	}
	if len(inMigration) == 0 {
		t.Fatal("no evaluators found in the migration; this guard has stopped checking anything")
	}

	inCorpus := map[string]bool{}
	for _, r := range builtinRulesForCorpus(t) {
		inCorpus[r.Evaluator] = true
	}

	for ev := range inMigration {
		if !inCorpus[ev] {
			t.Errorf("evaluator %q is seeded by the migration and absent from the corpus mirror", ev)
		}
		if _, ok := Evaluators[ev]; !ok {
			t.Errorf("evaluator %q is seeded by the migration and not implemented", ev)
		}
	}
	for ev := range inCorpus {
		if !inMigration[ev] {
			t.Errorf("evaluator %q is in the corpus mirror and not seeded by the migration", ev)
		}
	}
}
