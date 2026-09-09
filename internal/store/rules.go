package store

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
)

// Rules reads the global rule tables (ADR-009). No tenant_id: a rule is the same
// detection logic for every tenant, and these tables carry no RLS.
type Rules struct{}

// RuleRow is one rule as the engine consumes it. detection_logic is split into
// its evaluator name and params here rather than in the engine, so the engine
// never sees the raw jsonb envelope.
type RuleRow struct {
	ID          uuid.UUID
	Name        string
	Category    string
	Evaluator   string
	Params      json.RawMessage
	Severity    string
	Confidence  float64
	CWE         string
	Remediation string
	Version     int
}

// ActiveCoreRules returns the current version of every core-side rules-engine
// rule.
//
// ============================================================================
// The CURRENT version of each rule, and only core rules.
// ============================================================================
//
// `rules` keeps every version rather than overwriting (ADR-013: a months-old
// scan point emits months-old verdicts and Core must know which rule version
// produced one). This session evaluates at Core over fresh observations, so it
// wants the newest version of each rule — `DISTINCT ON (name) ... ORDER BY name,
// version DESC`. When scan-point rules and verdict attribution arrive, the
// lookup by (name, version) is a different query, not this one.
//
// Filtered to execution_site = 'core' and engine = 'rules': a scan-point rule is
// not Core's to evaluate, and a rule for another engine is not this engine's.
func (Rules) ActiveCoreRules(ctx context.Context, c *Conn) ([]RuleRow, error) {
	const q = `
		SELECT DISTINCT ON (name)
		       rule_id, name, category, default_severity, base_confidence,
		       coalesce(cwe, ''), detection_logic, coalesce(remediation_template, ''), version
		  FROM rules
		 WHERE execution_site = 'core' AND engine = 'rules'
		 ORDER BY name, version DESC`

	rows, err := c.Query(ctx, q)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []RuleRow
	for rows.Next() {
		var (
			r     RuleRow
			logic []byte
		)
		if err := rows.Scan(&r.ID, &r.Name, &r.Category, &r.Severity, &r.Confidence,
			&r.CWE, &logic, &r.Remediation, &r.Version); err != nil {
			return nil, mapError(err)
		}
		// Split the {evaluator, params} envelope here. A row whose
		// detection_logic is not that shape is a malformed rule, and the engine's
		// Load refuses it — but the split failing is itself the signal, so it is
		// surfaced rather than swallowed.
		var env struct {
			Evaluator string          `json:"evaluator"`
			Params    json.RawMessage `json:"params"`
		}
		if err := json.Unmarshal(logic, &env); err != nil {
			return nil, mapError(err)
		}
		r.Evaluator, r.Params = env.Evaluator, env.Params
		out = append(out, r)
	}
	return out, mapError(rows.Err())
}

// AdvisoryMatchRuleID returns the id of the single seeded advisory-version-match
// rule (migration 0039, ADR-070) — the rule every advisory finding hangs on to
// satisfy rule_id-always (ADR-009, non-negotiable #4), with the CVE carried in vuln_def_id.
// It is NOT an ActiveCoreRules row: that query filters engine='rules', and this
// rule is engine='advisory' so the rules engine never evaluates it. ErrNotFound
// if the seed is missing — the matcher must not invent a rule_id.
func (Rules) AdvisoryMatchRuleID(ctx context.Context, c *Conn) (uuid.UUID, error) {
	const q = `SELECT rule_id FROM rules
	            WHERE engine = 'advisory' AND name = 'advisory-version-match'
	            ORDER BY version DESC LIMIT 1`
	var id uuid.UUID
	if err := c.QueryRow(ctx, q).Scan(&id); err != nil {
		return uuid.Nil, mapError(err)
	}
	return id, nil
}
