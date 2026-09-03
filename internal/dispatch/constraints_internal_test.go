package dispatch

import (
	"testing"
	"time"

	"github.com/effaaykhan/cvap/internal/store"
)

func ptr(i int) *int { return &i }

// jp builds the policy-plus-scan pair constraintsFor takes. The scan's opt-in
// defaults to intrusive in these cases so that the POLICY ceiling is what the
// assertion is measuring; the interaction between the two has its own test.
func jp(p store.Policy) *store.JobPolicy {
	return &store.JobPolicy{Policy: p, ScanSafetyMode: store.SafetyIntrusive}
}

// noWindow is a fixed instant. Every policy in these cases has empty
// time_windows, which is unrestricted (ADR-037), so the value cannot matter —
// and pinning it means a test that starts failing at 22:00 is telling the truth
// about a bug rather than about the clock.
var noWindow = time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

// TestConstraintsTakeTheMinimumOfPlatformAndPolicy is ADR-024 control 2.
//
// The case that matters is "policy lowers": that is what was broken, and it was
// broken in the dangerous direction — a policy asking for 50 pps was handed
// 1,000, against an estate its operator had reason to be careful with.
func TestConstraintsTakeTheMinimumOfPlatformAndPolicy(t *testing.T) {
	for _, tc := range []struct {
		name                                 string
		policy                               *store.JobPolicy
		rate, perTarget, fragile, concurrent uint32
		mode                                 string
	}{
		{
			name:   "no policy at all falls back to the platform table",
			policy: nil,
			rate:   1000, perTarget: 50, fragile: 10, concurrent: 20, mode: "safe",
		},
		{
			name:   "NULL max_rate_pps means the platform default",
			policy: jp(store.Policy{SafetyMode: store.SafetySafe}),
			rate:   1000, perTarget: 50, fragile: 10, concurrent: 20, mode: "safe",
		},
		{
			name:   "a policy that lowers is honoured",
			policy: jp(store.Policy{SafetyMode: store.SafetySafe, MaxRatePPS: ptr(50)}),
			rate:   50, perTarget: 50, fragile: 10, concurrent: 20, mode: "safe",
		},
		{
			// The per-target ceiling must come down with it. A runtime told it
			// may send 50 pps at one host while the scan point's whole budget is
			// 5 has been authorised to exceed the policy tenfold at the single
			// place that matters most.
			name:   "per-target and fragile clamp beneath a very low policy rate",
			policy: jp(store.Policy{SafetyMode: store.SafetySafe, MaxRatePPS: ptr(5)}),
			rate:   5, perTarget: 5, fragile: 5, concurrent: 20,
			mode: "safe",
		},
		{
			// ADR-024 control 2 is lower-only. The column's CHECK bounds this
			// too; Core does not rely on it, because the place that must never
			// be wrong is the one deciding what goes on the wire.
			name:   "a policy that tries to raise is ignored",
			policy: jp(store.Policy{SafetyMode: store.SafetySafe, MaxRatePPS: ptr(5000)}),
			rate:   1000, perTarget: 50, fragile: 10, concurrent: 20, mode: "safe",
		},
		{
			// Not a quantity, so not minimised — but still reduced, by the scan
			// opt-in this helper sets to intrusive. Hardcoding "safe" meant an
			// intrusive policy silently ran safe, the failure that looks like
			// everything working.
			name:   "safety_mode passes through when the scan opted in",
			policy: jp(store.Policy{SafetyMode: store.SafetyIntrusive}),
			rate:   1000, perTarget: 50, fragile: 10, concurrent: 20, mode: "intrusive",
		},
		{
			// ADR-024's second lever, added in migration 0024. Connection count
			// rather than packet rate is what tips a printer over, so an
			// operator who lowered the rate and was still handed 20 concurrent
			// connections per host had not got what they asked for.
			name:   "a policy that lowers concurrency is honoured",
			policy: jp(store.Policy{SafetyMode: store.SafetySafe, MaxConcurrentPerTarget: ptr(2)}),
			rate:   1000, perTarget: 50, fragile: 10, concurrent: 2, mode: "safe",
		},
		{
			name:   "a policy that tries to raise concurrency is ignored",
			policy: jp(store.Policy{SafetyMode: store.SafetySafe, MaxConcurrentPerTarget: ptr(500)}),
			rate:   1000, perTarget: 50, fragile: 10, concurrent: 20, mode: "safe",
		},
		{
			// The wrap ADR-024 forbids, arrived at by arithmetic rather than by
			// anyone's decision. Bounded as int before the conversion.
			name:   "a negative concurrency row cannot wrap into a huge ceiling",
			policy: jp(store.Policy{SafetyMode: store.SafetySafe, MaxConcurrentPerTarget: ptr(-1)}),
			rate:   1000, perTarget: 50, fragile: 10, concurrent: 20, mode: "safe",
		},
		{
			name:   "the two levers are independent",
			policy: jp(store.Policy{SafetyMode: store.SafetySafe, MaxRatePPS: ptr(5), MaxConcurrentPerTarget: ptr(1)}),
			rate:   5, perTarget: 5, fragile: 5, concurrent: 1, mode: "safe",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := constraintsFor(tc.policy, nil, noWindow)
			if err != nil {
				t.Fatalf("constraintsFor: %v", err)
			}
			if got.GetMaxRatePps() != tc.rate {
				t.Errorf("max_rate_pps = %d, want %d", got.GetMaxRatePps(), tc.rate)
			}
			if got.GetMaxRatePerTarget() != tc.perTarget {
				t.Errorf("max_rate_per_target = %d, want %d", got.GetMaxRatePerTarget(), tc.perTarget)
			}
			if got.GetFragileRatePps() != tc.fragile {
				t.Errorf("fragile_rate_pps = %d, want %d", got.GetFragileRatePps(), tc.fragile)
			}
			if got.GetSafetyMode() != tc.mode {
				t.Errorf("safety_mode = %q, want %q", got.GetSafetyMode(), tc.mode)
			}
			if got.GetMaxConcurrentPerTarget() != tc.concurrent {
				t.Errorf("max_concurrent_per_target = %d, want %d",
					got.GetMaxConcurrentPerTarget(), tc.concurrent)
			}
			// Still not adjustable by policy; asserted so that adding a column
			// for it has to come here and think about the direction. ADR-024
			// says "adjust" rather than "lower only" for this one, which is a
			// decision to make deliberately rather than by writing a migration.
			if got.GetConnectTimeoutMs() != platformConnectTimeoutMs {
				t.Errorf("connect_timeout_ms = %d, want %d",
					got.GetConnectTimeoutMs(), platformConnectTimeoutMs)
			}
		})
	}
}

// TestScopePlanSplitsAllowsFromDenies covers the field whose empty value is now
// load-bearing: allowed_targets empty means DENY ALL.
func TestScopePlanSplitsAllowsFromDenies(t *testing.T) {
	rules := []store.ScopeRule{
		{Effect: store.ScopeDeny, MatchType: store.MatchCIDR, MatchValue: "10.10.0.5/32"},
		{Effect: store.ScopeAllow, MatchType: store.MatchCIDR, MatchValue: "10.10.0.0/24"},
		{Effect: store.ScopeAllow, MatchType: store.MatchHostname, MatchValue: "lab.internal"},
	}

	allowed, exclusions, err := scopePlan(rules)
	if err != nil {
		t.Fatalf("scopePlan: %v", err)
	}
	if len(allowed) != 2 || allowed[0] != "10.10.0.0/24" || allowed[1] != "lab.internal" {
		t.Errorf("allowed_targets = %v, want both allows", allowed)
	}
	if len(exclusions) != 1 || exclusions[0] != "10.10.0.5/32" {
		t.Errorf("exclusions = %v, want the one deny", exclusions)
	}
}

// TestUnexpressibleRulesFailTheJobRatherThanVanish is the fix for a fail-open
// asymmetry a safety audit found.
//
// The first version skipped `tag` rules before looking at their effect. Dropping
// a tag ALLOW fails closed — the allowlist shrinks. Dropping a tag DENY fails
// OPEN: "allow 10.10.0.0/24, deny tag medical" produced a non-empty allowlist,
// so the job dispatched with no warning at all, and the exclusion protecting the
// medical devices inside that range reached neither enforcement site. ADR-024
// says exclusions take precedence over allows, and a precedence that can be
// deleted by choosing a match type is not one.
func TestUnexpressibleRulesFailTheJobRatherThanVanish(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rules []store.ScopeRule
	}{
		{"a tag deny cannot silently vanish", []store.ScopeRule{
			{Effect: store.ScopeAllow, MatchType: store.MatchCIDR, MatchValue: "10.10.0.0/24"},
			{Effect: store.ScopeDeny, MatchType: store.MatchTag, MatchValue: "medical"},
		}},
		{"a tag allow fails the same way, for symmetry", []store.ScopeRule{
			{Effect: store.ScopeAllow, MatchType: store.MatchTag, MatchValue: "production"},
		}},
		{"an unparseable deny CIDR is a rule nothing can evaluate", []store.ScopeRule{
			{Effect: store.ScopeDeny, MatchType: store.MatchCIDR, MatchValue: "10.0.0.0/33"},
		}},
		{"an unparseable allow CIDR too", []store.ScopeRule{
			{Effect: store.ScopeAllow, MatchType: store.MatchCIDR, MatchValue: "not-a-cidr"},
		}},
		{"an empty hostname", []store.ScopeRule{
			{Effect: store.ScopeDeny, MatchType: store.MatchHostname, MatchValue: "  "},
		}},
		{"a match type nobody taught this switch about", []store.ScopeRule{
			{Effect: store.ScopeAllow, MatchType: store.ScopeMatchType("geo"), MatchValue: "eu"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := scopePlan(tc.rules); err == nil {
				t.Error("scopePlan accepted a rule it cannot express on the wire; a rule that " +
					"reaches neither enforcement site must fail the job, not disappear")
			}
			if _, err := constraintsFor(jp(store.Policy{SafetyMode: store.SafetySafe}), tc.rules, noWindow); err == nil {
				t.Error("constraintsFor built an assignment from unexpressible rules")
			}
		})
	}
}
