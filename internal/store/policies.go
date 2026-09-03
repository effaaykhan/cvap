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

// PolicySpec is a policy as an operator writes it.
//
// AllowedEngines, AllowedZones and TimeWindows are raw jsonb, for the reason
// Policy.TimeWindows gives: the store does not own the encoding. The API
// validates the shapes it accepts before they get here.
type PolicySpec struct {
	Name                   string
	SafetyMode             SafetyMode
	MaxRatePPS             *int
	MaxConcurrentPerTarget *int
	TimeWindows            []byte
	AllowedEngines         []byte
	AllowedZones           []byte
}

// Create writes a policy.
//
// safety_mode is settable here, unlike on a scan, and the asymmetry is ADR-021's:
// the policy is the CEILING an operator sets deliberately, and the per-scan
// opt-in is what has to be explicit each time. A policy created as intrusive
// authorises nothing on its own — every scan under it still defaults to safe.
func (Policies) Create(ctx context.Context, c *Conn, spec PolicySpec) (*Policy, error) {
	const q = `
		INSERT INTO scan_policies
			(tenant_id, name, safety_mode, max_rate_pps, max_concurrent_per_target,
			 time_windows, allowed_engines, allowed_zones)
		VALUES ($1, $2, $3::text::safety_mode, $4, $5,
		        coalesce($6::jsonb, '[]'::jsonb),
		        coalesce($7::jsonb, '[]'::jsonb),
		        coalesce($8::jsonb, '[]'::jsonb))
		RETURNING policy_id, name, safety_mode, max_rate_pps, max_concurrent_per_target, time_windows`

	var p Policy
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), spec.Name, string(spec.SafetyMode),
		spec.MaxRatePPS, spec.MaxConcurrentPerTarget,
		nullJSON(spec.TimeWindows), nullJSON(spec.AllowedEngines), nullJSON(spec.AllowedZones)).
		Scan(&p.ID, &p.Name, &p.SafetyMode, &p.MaxRatePPS, &p.MaxConcurrentPerTarget, &p.TimeWindows)
	if err != nil {
		return nil, mapError(err)
	}
	return &p, nil
}

// Update replaces a policy's fields.
//
// A full replacement rather than a patch. A patch over a policy means a client
// that omits allowed_zones leaves the old value — which for a field where empty
// means unrestricted (ADR-037) makes "I did not send it" and "I sent nothing"
// two different things that look identical in a request body.
func (Policies) Update(ctx context.Context, c *Conn, policyID uuid.UUID, spec PolicySpec) (*Policy, error) {
	const q = `
		UPDATE scan_policies
		   SET name = $3, safety_mode = $4::text::safety_mode,
		       max_rate_pps = $5, max_concurrent_per_target = $6,
		       time_windows    = coalesce($7::jsonb, '[]'::jsonb),
		       allowed_engines = coalesce($8::jsonb, '[]'::jsonb),
		       allowed_zones   = coalesce($9::jsonb, '[]'::jsonb),
		       updated_at = now()
		 WHERE tenant_id = $1 AND policy_id = $2
		RETURNING policy_id, name, safety_mode, max_rate_pps, max_concurrent_per_target, time_windows`

	var p Policy
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), policyID, spec.Name, string(spec.SafetyMode),
		spec.MaxRatePPS, spec.MaxConcurrentPerTarget,
		nullJSON(spec.TimeWindows), nullJSON(spec.AllowedEngines), nullJSON(spec.AllowedZones)).
		Scan(&p.ID, &p.Name, &p.SafetyMode, &p.MaxRatePPS, &p.MaxConcurrentPerTarget, &p.TimeWindows)
	if err != nil {
		return nil, mapError(err)
	}
	return &p, nil
}

// Get returns one policy.
func (Policies) Get(ctx context.Context, c *Conn, policyID uuid.UUID) (*Policy, error) {
	const q = `
		SELECT policy_id, name, safety_mode, max_rate_pps, max_concurrent_per_target, time_windows
		  FROM scan_policies WHERE tenant_id = $1 AND policy_id = $2`

	var p Policy
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), policyID).
		Scan(&p.ID, &p.Name, &p.SafetyMode, &p.MaxRatePPS, &p.MaxConcurrentPerTarget, &p.TimeWindows)
	if err != nil {
		return nil, mapError(err)
	}
	return &p, nil
}

// List returns every policy for the tenant, by name.
func (Policies) List(ctx context.Context, c *Conn) ([]Policy, error) {
	const q = `
		SELECT policy_id, name, safety_mode, max_rate_pps, max_concurrent_per_target, time_windows
		  FROM scan_policies WHERE tenant_id = $1 ORDER BY name, policy_id`

	rows, err := c.Query(ctx, q, c.Tenant().UUID())
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []Policy
	for rows.Next() {
		var p Policy
		if err := rows.Scan(&p.ID, &p.Name, &p.SafetyMode, &p.MaxRatePPS,
			&p.MaxConcurrentPerTarget, &p.TimeWindows); err != nil {
			return nil, mapError(err)
		}
		out = append(out, p)
	}
	return out, mapError(rows.Err())
}

// AddScopeRule appends one allow or deny entry to a policy.
func (Policies) AddScopeRule(ctx context.Context, c *Conn, policyID uuid.UUID, r ScopeRule) (*ScopeRule, error) {
	const q = `
		INSERT INTO policy_scope_rules
			(tenant_id, policy_id, effect, match_type, match_value, precedence)
		VALUES ($1, $2, $3::text::scope_rule_effect, $4::text::scope_match_type, $5, $6)
		RETURNING scope_rule_id, effect, match_type, match_value, precedence`

	var out ScopeRule
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), policyID, string(r.Effect),
		string(r.MatchType), r.MatchValue, r.Precedence).
		Scan(&out.ID, &out.Effect, &out.MatchType, &out.MatchValue, &out.Precedence)
	if err != nil {
		return nil, mapError(err)
	}
	return &out, nil
}

// DeleteScopeRule removes one entry.
//
// ============================================================================
// Deleting a DENY rule widens what may be scanned.
// ============================================================================
//
// It returns ErrNotFound rather than succeeding silently when nothing matched,
// because "the exclusion is gone" and "the exclusion was never there" are the
// same observable outcome for a caller that does not check — and an operator who
// believes they removed the wrong rule will go looking for a different
// explanation for the scan that follows.
func (Policies) DeleteScopeRule(ctx context.Context, c *Conn, policyID, ruleID uuid.UUID) error {
	const q = `
		DELETE FROM policy_scope_rules
		 WHERE tenant_id = $1 AND policy_id = $2 AND scope_rule_id = $3
		RETURNING scope_rule_id`

	var got uuid.UUID
	return mapError(c.QueryRow(ctx, q, c.Tenant().UUID(), policyID, ruleID).Scan(&got))
}

// nullJSON turns an empty byte slice into a NULL, so the coalesce in each
// statement supplies the column default rather than failing on invalid JSON.
func nullJSON(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}
