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

// Policy is the half of a scan policy that reaches the wire.
//
// MaxRatePPS is nullable and LOWER-ONLY (ADR-024 control 2): NULL means the
// platform default, and a value may only reduce it. The column's CHECK bounds it
// at the current default, but the authoritative comparison happens in Core —
// a ceiling enforced in one place is decorative, and the place that must never
// be wrong is the one deciding what goes on the wire.
type Policy struct {
	ID         uuid.UUID
	Name       string
	SafetyMode SafetyMode
	MaxRatePPS *int
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
func (Policies) ForJob(ctx context.Context, c *Conn, jobID uuid.UUID) (*Policy, error) {
	const q = `
		SELECT p.policy_id, p.name, p.safety_mode, p.max_rate_pps
		  FROM scan_jobs j
		  JOIN scans s   ON s.tenant_id = j.tenant_id AND s.scan_id = j.scan_id
		  JOIN scan_policies p ON p.tenant_id = s.tenant_id AND p.policy_id = s.policy_id
		 WHERE j.tenant_id = $1 AND j.job_id = $2`

	var p Policy
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), jobID).
		Scan(&p.ID, &p.Name, &p.SafetyMode, &p.MaxRatePPS)
	if err != nil {
		return nil, mapError(err)
	}
	return &p, nil
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
