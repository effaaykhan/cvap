package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// SafetyMode mirrors the safety_mode enum (ADR-021).
type SafetyMode string

const (
	SafetySafe      SafetyMode = "safe"
	SafetyIntrusive SafetyMode = "intrusive"
)

// ScopeRuleEffect and ScopeMatchType mirror their enums.
type (
	ScopeRuleEffect string
	ScopeMatchType  string
)

const (
	ScopeAllow ScopeRuleEffect = "allow"
	ScopeDeny  ScopeRuleEffect = "deny"

	MatchCIDR     ScopeMatchType = "cidr"
	MatchHostname ScopeMatchType = "hostname"
	MatchURL      ScopeMatchType = "url"
	MatchTag      ScopeMatchType = "tag"
)

// Policy is the part of a scan policy dispatch reads.
//
// MaxRatePPS and MaxConcurrentPerTarget are nullable and LOWER-ONLY (ADR-024
// control 2): NULL means the platform default, and a value may only reduce it.
// The columns' CHECKs bound them at the current defaults, but the authoritative
// comparison happens in Core — a ceiling enforced in one place is decorative,
// and the place that must never be wrong is the one deciding what goes on the
// wire.
type Policy struct {
	ID         uuid.UUID
	Name       string
	SafetyMode SafetyMode
	MaxRatePPS *int

	// MaxConcurrentPerTarget is the second ADR-024 lever, and not a derivative
	// of the first: a host answering 20 simultaneous connects at 5 pps is under
	// more pressure than one answering a single connection at 50 pps, and
	// connection count is what tips a printer over.
	MaxConcurrentPerTarget *int

	// TimeWindows is scan_policies.time_windows verbatim.
	//
	// Raw rather than parsed because the store does not own the encoding: the
	// windows are evaluated in dispatch, where the result becomes
	// ScanConstraints.window_ends_unix, and one parser in one place is the point
	// (see internal/dispatch/windows.go). EMPTY MEANS UNRESTRICTED — the
	// opposite of allowed_targets, for the reason ADR-037 records.
	TimeWindows []byte
}

// JobPolicy is everything governing one job: its scan's policy, plus the
// per-scan choices that sit BENEATH the policy's ceilings.
//
// Two sources rather than one because ADR-021 splits them deliberately. The
// policy says what a scan is permitted to do; the scan says what it opted into.
// Collapsing them onto Policy would make scans.safety_mode look like a policy
// column, which is exactly the confusion the per-scan opt-in exists to prevent —
// a policy left on intrusive after a test window must not authorise anything on
// its own.
type JobPolicy struct {
	Policy

	// ScanSafetyMode is scans.safety_mode: the per-scan opt-in. The effective
	// mode is the LOWER of this and Policy.SafetyMode, and a scan may only
	// lower. Defaults to safe for every scan, including every one that existed
	// before the column did.
	ScanSafetyMode SafetyMode
}

// ScopeRule is one allow or deny entry. Exclusions take precedence over allows
// regardless of precedence value (ADR-024); precedence orders within an effect.
type ScopeRule struct {
	ID         uuid.UUID
	Effect     ScopeRuleEffect
	MatchType  ScopeMatchType
	MatchValue string
	Precedence int
}

type Policies struct{}

// ForJob returns the policy governing a job, through its scan.
//
// Dispatch needs this on the assignment path: constraints built from platform
// defaults alone ignore a policy that lowered them, which inverts ADR-024. A
// policy asking for 50 pps was getting 1000.
func (Policies) ForJob(ctx context.Context, c *Conn, jobID uuid.UUID) (*JobPolicy, error) {
	const q = `
		SELECT p.policy_id, p.name, p.safety_mode, p.max_rate_pps,
		       p.max_concurrent_per_target, p.time_windows, s.safety_mode
		  FROM scan_jobs j
		  JOIN scans s   ON s.tenant_id = j.tenant_id AND s.scan_id = j.scan_id
		  JOIN scan_policies p ON p.tenant_id = s.tenant_id AND p.policy_id = s.policy_id
		 WHERE j.tenant_id = $1 AND j.job_id = $2`

	var jp JobPolicy
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), jobID).
		Scan(&jp.ID, &jp.Name, &jp.SafetyMode, &jp.MaxRatePPS,
			&jp.MaxConcurrentPerTarget, &jp.TimeWindows, &jp.ScanSafetyMode)
	if err != nil {
		return nil, mapError(err)
	}
	return &jp, nil
}

// MaxWindowedPolicies bounds one tenant's windowed-policy read.
//
// Dispatch asks "which policies in this tenant are outside their maintenance
// window right now" on every poll, and uses the answer to keep those policies'
// jobs unclaimed. Truncating that answer would leave a closed policy off the
// list and dispatch its jobs outside the window it was written to protect, so
// the read fails instead — and a failed read assigns nothing, which is the
// direction a scan window has to fail in.
const MaxWindowedPolicies = 1000

// ErrTooManyWindowedPolicies means a tenant's windowed policies cannot be
// evaluated in one pass.
var ErrTooManyWindowedPolicies = errors.New("store: tenant has more windowed policies than one dispatch pass can evaluate")

// PolicyWindows is one policy's maintenance windows, unparsed.
type PolicyWindows struct {
	PolicyID    uuid.UUID
	TimeWindows []byte
}

// WithTimeWindows returns the tenant's policies that restrict WHEN they may run.
//
// Only policies with a non-empty time_windows come back, which is what the
// partial index in migration 0024 is for: almost no policy has a window, and
// this runs on the dispatch poll. A policy absent from this result is
// unrestricted in time (ADR-037), not "closed by default" — the empty list is
// the answer to "is this scan restricted", and an unset restriction is none.
func (Policies) WithTimeWindows(ctx context.Context, c *Conn) ([]PolicyWindows, error) {
	const q = `
		SELECT policy_id, time_windows
		  FROM scan_policies
		 WHERE tenant_id = $1 AND jsonb_array_length(time_windows) > 0
		 ORDER BY policy_id
		 LIMIT $2`

	// One past the cap, so an oversized tenant is detected rather than trimmed.
	rows, err := c.Query(ctx, q, c.Tenant().UUID(), MaxWindowedPolicies+1)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []PolicyWindows
	for rows.Next() {
		var w PolicyWindows
		if err := rows.Scan(&w.PolicyID, &w.TimeWindows); err != nil {
			return nil, mapError(err)
		}
		out = append(out, w)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(err)
	}
	if len(out) > MaxWindowedPolicies {
		return nil, fmt.Errorf("%w: more than %d", ErrTooManyWindowedPolicies, MaxWindowedPolicies)
	}
	return out, nil
}

// MaxScopeRulesPerAssignment bounds what one policy can put on the wire.
//
// Same reasoning as MaxTasksPerAssignment, on a different field of the same
// message: the scope lists travel inside JobAssignment against a 4MB cap, so an
// unbounded read produces a Send that fails AFTER the job is assigned and
// leased. Refusing is better than truncating for the same reason again, and more
// sharply here — a truncated EXCLUSION list is a scan authorised against hosts
// its policy denies.
const MaxScopeRulesPerAssignment = 2000

// ErrTooManyScopeRules means a policy cannot be expressed in one assignment.
var ErrTooManyScopeRules = errors.New("store: policy has more scope rules than one assignment can carry")

// ScopeRules returns a policy's scope rules in evaluation order.
//
// Deny first, then by precedence. The ordering is cosmetic for the wire — the
// scan point evaluates exclusions ahead of allows whatever order they arrive in,
// because ADR-024 says exclusions take precedence regardless — but a caller
// reading these to explain a decision to an operator should see them the way
// they are evaluated.
func (Policies) ScopeRules(ctx context.Context, c *Conn, policyID uuid.UUID) ([]ScopeRule, error) {
	const q = `
		SELECT scope_rule_id, effect, match_type, match_value, precedence
		  FROM policy_scope_rules
		 WHERE tenant_id = $1 AND policy_id = $2
		 ORDER BY (effect = 'deny') DESC, precedence, match_value
		 LIMIT $3`

	// One past the cap, so an oversized policy is detected rather than trimmed.
	rows, err := c.Query(ctx, q, c.Tenant().UUID(), policyID, MaxScopeRulesPerAssignment+1)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []ScopeRule
	for rows.Next() {
		var r ScopeRule
		if err := rows.Scan(&r.ID, &r.Effect, &r.MatchType, &r.MatchValue, &r.Precedence); err != nil {
			return nil, mapError(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(err)
	}
	if len(out) > MaxScopeRulesPerAssignment {
		return nil, fmt.Errorf("%w: policy %s has more than %d scope rules",
			ErrTooManyScopeRules, policyID, MaxScopeRulesPerAssignment)
	}
	return out, nil
}
