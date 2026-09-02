package dispatch

import (
	"testing"

	"github.com/effaaykhan/cvap/internal/store"
)

// TestIntrusiveNeedsBothThePolicyCeilingAndTheScanOptIn is ADR-021.
//
// "Safe mode is the default for every policy; intrusive requires explicit
// per-scan opt-in." Before scans.safety_mode existed there was nothing to opt in
// with, so one policy flipped to intrusive standing-authorised every scan ever
// bound to it — including scheduled ones nobody looked at again. A policy left on
// intrusive after a test window is the exact failure the ADR was written
// against, and it is the top-right cell below.
//
// The bottom-left cell is the other half: a scan cannot raise itself above its
// policy. store.Scans.SetSafetyMode refuses to write that combination at all;
// this asserts that even if it existed in the database, it would not reach the
// wire. A ceiling enforced in one place is decorative.
func TestIntrusiveNeedsBothThePolicyCeilingAndTheScanOptIn(t *testing.T) {
	for _, tc := range []struct {
		name         string
		policy, scan store.SafetyMode
		want         string
	}{
		{"both intrusive", store.SafetyIntrusive, store.SafetyIntrusive, "intrusive"},
		{"policy intrusive, scan did not opt in", store.SafetyIntrusive, store.SafetySafe, "safe"},
		{"scan asks for more than its policy permits", store.SafetySafe, store.SafetyIntrusive, "safe"},
		{"neither", store.SafetySafe, store.SafetySafe, "safe"},

		// A row written before either column had a value cannot be read as an
		// authorisation. Unset is safe in both positions.
		{"an unset policy mode", "", store.SafetyIntrusive, "safe"},
		{"an unset scan mode", store.SafetyIntrusive, "", "safe"},
		{"both unset", "", "", "safe"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &store.JobPolicy{
				Policy:         store.Policy{SafetyMode: tc.policy},
				ScanSafetyMode: tc.scan,
			}
			got, err := constraintsFor(p, nil, noWindow)
			if err != nil {
				t.Fatalf("constraintsFor: %v", err)
			}
			if got.GetSafetyMode() != tc.want {
				t.Errorf("safety_mode = %q, want %q (policy %q, scan %q)",
					got.GetSafetyMode(), tc.want, tc.policy, tc.scan)
			}
		})
	}
}

// TestClampCountKeepsTheAcknowledgement.
//
// tasks_halted arrives as a uint32 from a network whose compromise the threat
// model assumes (ADR-020) and lands in a Postgres int4. Without the clamp, a
// value above 2^31-1 fails the INSERT — and the acknowledgement is the part
// ADR-024 needs, not the count beside it. Losing the ack to a bad number makes a
// kill read as unacknowledged forever.
func TestClampCountKeepsTheAcknowledgement(t *testing.T) {
	for _, tc := range []struct {
		in   uint32
		want int
	}{
		{0, 0},
		{7, 7},
		{1<<31 - 1, 1<<31 - 1},
		{1 << 31, 1<<31 - 1},
		{^uint32(0), 1<<31 - 1},
	} {
		if got := clampCount(tc.in); got != tc.want {
			t.Errorf("clampCount(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
