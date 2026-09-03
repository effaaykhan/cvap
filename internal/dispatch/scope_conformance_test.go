package dispatch

import (
	"testing"

	"github.com/effaaykhan/cvap/internal/scope"
	"github.com/effaaykhan/cvap/internal/scope/scopetest"
)

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
func TestCoreSiteAgreesWithTheSharedTable(t *testing.T) {
	coreVerdict := func(target string, allowed, exclusions []string) bool {
		ok, _ := scope.Permits(target, allowed, exclusions)
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
