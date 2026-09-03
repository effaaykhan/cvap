package dispatch

import (
	"testing"

	"github.com/effaaykhan/cvap/internal/scope"
	"github.com/effaaykhan/cvap/internal/scope/scopetest"
	"github.com/effaaykhan/cvap/internal/target"
)

// Mutations, declared beside the tests that must kill them.
//
// This driver WAS a paraphrase of the wrong expression for one session — it
// called Canonicalise where offerWork calls Matches, so the Core half of
// ADR-024's two-site agreement was asserted against a path Core does not run.
// An ADR-compliance pass found it by reading. The first mutation below is that
// exact drift, so the next one is found by the build.
//
// mutate:subject internal/dispatch/dispatch.go
// mutate:test    ./internal/dispatch/ -run TestCoreSiteAgreesWithTheSharedTable|TestOutOfScopeTaskIsRefused|TestANonCanonicalTaskTargetRefusesTheJob
//
// mutate:case    Core validates the canonical form instead of re-computing it
// mutate:old     canon, canonical := target.Matches(t.TaskTarget)
// mutate:new     canon, canonical := func(v string) (target.Canonical, bool) { c, err := target.Canonicalise(v); return c, err == nil }(t.TaskTarget)
//
// mutate:case    Core does not check canonicality at all
// mutate:old     ok, why := canonical, "target is not in canonical form"
// mutate:new     ok, why := true, ""
//
// mutate:subject internal/scope/scope.go
//
// mutate:case    exclusions no longer take precedence over allows
// mutate:old     if matchesExclusion(e, targetStr, addr, isAddr) {
// mutate:new     if false {
//
// TestCoreSiteAgreesWithTheSharedTable is one half of ADR-024's "both sides must
// evaluate identically".
//
// internal/scanpoint has the mirror of this file, over the same table. Sharing
// internal/scope makes the two evaluate rules the same way; it does not make
// them CALL it the same way, and the call is where a site drifts. A Core that
// stopped passing exclusions, or passed the allowlist twice, or skipped the
// check for a class of target would compile, pass every other test in this
// package, and quietly authorise work the runtime would refuse.
//
// coreVerdict is deliberately the expression offerWork uses, not a paraphrase of
// it. If that line changes, this test has to change with it, which is the point:
// the assertion is about the call site, not about the matcher.
//
// It was a paraphrase for one session, and an ADR-compliance pass caught it.
// The driver called Canonicalise where offerWork calls Matches — which normalises
// AND requires equality with the received bytes — so the two gave opposite
// answers for every non-canonical case in the table, and the assertion was
// against a code path Core does not run.
//
// The shape below is what actually happens, in order:
//
//  1. PLANNING canonicalises the operator's string and writes the result to
//     scan_tasks.task_target (ADR-044). The table's Target column is that
//     operator string, so this step belongs here.
//  2. offerWork re-computes over the stored value with target.Matches and then
//     matches, because the row can be written by something that skipped step 1.
//
// Both steps, because leaving either out tests something Core does not do.
func TestCoreSiteAgreesWithTheSharedTable(t *testing.T) {
	coreVerdict := func(raw string, allowed, exclusions []string) bool {
		// Step 1: planning. A target with no canonical form is not planned at
		// all (ADR-040), which is a denial here.
		planned, err := target.Canonicalise(raw)
		if err != nil {
			return false
		}
		// Step 2: the expression offerWork uses, verbatim, over what planning
		// stored.
		canon, canonical := target.Matches(planned.Value)
		if !canonical {
			return false
		}
		ok, _ := scope.Permits(canon, allowed, exclusions)
		return ok
	}

	for _, tc := range scopetest.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			if got := coreVerdict(tc.Target, tc.Allowed, tc.Exclusions); got != tc.Want {
				t.Errorf("Core-side verdict for %q = %v, want %v. The scan point runtime "+
					"decides the same case in internal/scanpoint; a disagreement is a "+
					"target one side permits and the other refuses, and neither direction "+
					"announces itself at runtime.", tc.Target, got, tc.Want)
			}
		})
	}
}
