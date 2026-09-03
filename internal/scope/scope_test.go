package scope_test

import (
	"testing"

	"github.com/effaaykhan/cvap/internal/scope"
	"github.com/effaaykhan/cvap/internal/scope/scopetest"
)

// TestPermitsOverTheSharedTable is the matcher's own test.
//
// The two conformance suites — one in internal/dispatch, one in
// internal/scanpoint — run the same table through each site's decision path. This
// one runs it through the function directly, so a failure here means the matcher
// is wrong, and a failure there with this passing means a CALLER is wrong. That
// separation is the reason the table lives in its own package.
func TestPermitsOverTheSharedTable(t *testing.T) {
	for _, tc := range scopetest.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			got, why := scope.Permits(tc.Target, tc.Allowed, tc.Exclusions)
			if got != tc.Want {
				t.Errorf("Permits(%q, allow=%v, deny=%v) = %v (%s), want %v",
					tc.Target, tc.Allowed, tc.Exclusions, got, why, tc.Want)
			}
			if !got && why == "" {
				t.Error("a refusal with no reason; the reason reaches an audit event and an operator")
			}
		})
	}
}

// TestARefusalAlwaysSaysWhy. refuseJob puts this string in a job.scope_refused
// audit event and the runtime puts it in a log line an operator reads during an
// incident. An empty one turns "the scan stopped" into a mystery.
func TestARefusalAlwaysSaysWhy(t *testing.T) {
	for _, tc := range []struct{ target string }{
		{""}, {"198.51.100.1"}, {"192.0.2.5"},
	} {
		if ok, why := scope.Permits(tc.target, []string{"192.0.2.0/24"}, []string{"192.0.2.5"}); !ok && why == "" {
			t.Errorf("Permits(%q) refused with no reason", tc.target)
		}
	}
}
