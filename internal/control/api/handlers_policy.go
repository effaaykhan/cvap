package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"

	"github.com/effaaykhan/cvap/internal/store"
	"github.com/effaaykhan/cvap/internal/target"
)

// PolicyRequest is a policy as written through the API.
//
// The empty-list asymmetry is the thing to get right here, and it is ADR-037's:
//
//   - allowed_targets is a PERMISSION list. Empty means DENY. It is not a field
//     on this type at all — scope rules are their own endpoint, because an
//     allowlist that can be replaced wholesale by a PUT is an allowlist that a
//     partial request can empty.
//   - allowed_zones and time_windows are CONSTRAINT lists. Empty means
//     UNRESTRICTED. Both are fields here, and both are replaced wholesale,
//     because for a constraint list "I sent nothing" and "I sent an empty list"
//     genuinely are the same statement.
type PolicyRequest struct {
	Name                   string   `json:"name"`
	SafetyMode             string   `json:"safety_mode" doc:"safe | intrusive. The CEILING. A scan under an intrusive policy is still safe until it opts in (ADR-021)."`
	MaxRatePPS             *int     `json:"max_rate_pps,omitempty" doc:"Lower-only. The platform ceiling applies regardless, at Core and again at the scan point."`
	MaxConcurrentPerTarget *int     `json:"max_concurrent_per_target,omitempty" doc:"Lower-only. Connection count, not rate: a host answering 20 simultaneous connects at 5pps is under more pressure than one answering a single connection at 50pps."`
	TimeWindows            []string `json:"time_windows" doc:"CONSTRAINT list: empty means unrestricted (ADR-037)."`
	AllowedEngines         []string `json:"allowed_engines" doc:"CONSTRAINT list: empty means unrestricted (ADR-037)."`
	AllowedZones           []string `json:"allowed_zones" doc:"CONSTRAINT list: empty means unrestricted (ADR-037)."`
}

type PolicyResponse struct {
	ID                     string `json:"id"`
	Name                   string `json:"name"`
	SafetyMode             string `json:"safety_mode"`
	MaxRatePPS             *int   `json:"max_rate_pps,omitempty"`
	MaxConcurrentPerTarget *int   `json:"max_concurrent_per_target,omitempty"`
}

type PolicyListResponse struct {
	Policies []PolicyResponse `json:"policies"`
}

func policyResponse(p *store.Policy) PolicyResponse {
	return PolicyResponse{
		ID: p.ID.String(), Name: p.Name, SafetyMode: string(p.SafetyMode),
		MaxRatePPS: p.MaxRatePPS, MaxConcurrentPerTarget: p.MaxConcurrentPerTarget,
	}
}

// policySpec validates a request and turns it into a store spec.
func (s *Server) policySpec(w http.ResponseWriter, r *http.Request, req PolicyRequest) (store.PolicySpec, bool) {
	if req.Name == "" {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "name is required.", nil)
		return store.PolicySpec{}, false
	}
	mode := store.SafetyMode(req.SafetyMode)
	if mode != store.SafetySafe && mode != store.SafetyIntrusive {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"safety_mode must be safe or intrusive.", nil)
		return store.PolicySpec{}, false
	}
	if req.MaxRatePPS != nil && *req.MaxRatePPS <= 0 {
		// Zero would be stored and would mean "no packets", which is a scan
		// that completes reporting nothing. Refused so it cannot be typed by
		// accident; a policy that should not scan is not created.
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"max_rate_pps must be positive.", nil)
		return store.PolicySpec{}, false
	}
	if req.MaxConcurrentPerTarget != nil && *req.MaxConcurrentPerTarget <= 0 {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"max_concurrent_per_target must be positive.", nil)
		return store.PolicySpec{}, false
	}

	windows, _ := json.Marshal(nonNil(req.TimeWindows))
	engines, _ := json.Marshal(nonNil(req.AllowedEngines))
	zones, _ := json.Marshal(nonNil(req.AllowedZones))

	return store.PolicySpec{
		Name: req.Name, SafetyMode: mode,
		MaxRatePPS: req.MaxRatePPS, MaxConcurrentPerTarget: req.MaxConcurrentPerTarget,
		TimeWindows: windows, AllowedEngines: engines, AllowedZones: zones,
	}, true
}

// nonNil turns a nil slice into an empty one, so it marshals as [] rather than
// null. The columns are NOT NULL jsonb defaulting to '[]', and a null would fail
// the insert with a message about a column the caller cannot see.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (s *Server) createPolicy(w http.ResponseWriter, r *http.Request) {
	var req PolicyRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"The request body could not be read as this endpoint's schema.", err)
		return
	}
	spec, ok := s.policySpec(w, r, req)
	if !ok {
		return
	}

	tenant, _ := tenantFrom(r.Context())
	var p *store.Policy
	err := s.db.Write(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		p, err = (store.Policies{}).Create(ctx, c, spec)
		if err != nil {
			return err
		}
		id := p.ID
		return (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
			ActorID: actor(r), ActorType: store.ActorUser,
			Action: "policy.created", ResourceType: "scan_policy", ResourceID: &id,
			Detail: map[string]any{"name": spec.Name, "safety_mode": string(spec.SafetyMode)},
		})
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}
	writeJSON(w, r, s.log, http.StatusCreated, policyResponse(p))
}

func (s *Server) updatePolicy(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "policy_id")
	if err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "policy_id is not a uuid.", err)
		return
	}
	var req PolicyRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"The request body could not be read as this endpoint's schema.", err)
		return
	}
	spec, ok := s.policySpec(w, r, req)
	if !ok {
		return
	}

	tenant, _ := tenantFrom(r.Context())
	var p *store.Policy
	err = s.db.Write(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		p, err = (store.Policies{}).Update(ctx, c, id, spec)
		if err != nil {
			return err
		}
		pid := id
		// Policy edits are audited with the resulting ceiling, because a policy
		// raised to intrusive is the change an investigation will be looking
		// for and the row afterwards does not say when it happened.
		return (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
			ActorID: actor(r), ActorType: store.ActorUser,
			Action: "policy.updated", ResourceType: "scan_policy", ResourceID: &pid,
			Detail: map[string]any{"name": spec.Name, "safety_mode": string(spec.SafetyMode)},
		})
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}
	writeJSON(w, r, s.log, http.StatusOK, policyResponse(p))
}

func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "policy_id")
	if err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "policy_id is not a uuid.", err)
		return
	}
	tenant, _ := tenantFrom(r.Context())
	var p *store.Policy
	err = s.db.Read(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		p, err = (store.Policies{}).Get(ctx, c, id)
		return err
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}
	writeJSON(w, r, s.log, http.StatusOK, policyResponse(p))
}

func (s *Server) listPolicies(w http.ResponseWriter, r *http.Request) {
	tenant, _ := tenantFrom(r.Context())
	var ps []store.Policy
	err := s.db.Read(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		ps, err = (store.Policies{}).List(ctx, c)
		return err
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}
	out := PolicyListResponse{Policies: make([]PolicyResponse, 0, len(ps))}
	for i := range ps {
		out.Policies = append(out.Policies, policyResponse(&ps[i]))
	}
	writeJSON(w, r, s.log, http.StatusOK, out)
}

// ScopeRuleRequest adds one allow or deny entry.
type ScopeRuleRequest struct {
	Effect    string `json:"effect" doc:"allow | deny. Exclusions take precedence over allows regardless of precedence value (ADR-024)."`
	MatchType string `json:"match_type" doc:"cidr | hostname | url. A url rule is stored as the host it would reach, because scope authorises hosts (ADR-040). tag is not accepted: dispatch cannot express it on the wire and a policy carrying one refuses every job under it."`

	// A url match_value is reduced to its host before storage, so the stored
	// rule is the thing the matcher can actually compare against.
	MatchValue string `json:"match_value"`
	Precedence int    `json:"precedence,omitempty" doc:"Orders within an effect. Does not order deny against allow."`
}

type ScopeRuleResponse struct {
	ID         string `json:"id"`
	Effect     string `json:"effect"`
	MatchType  string `json:"match_type"`
	MatchValue string `json:"match_value"`
	Precedence int    `json:"precedence"`
}

type ScopeRuleListResponse struct {
	Rules []ScopeRuleResponse `json:"rules"`
}

var (
	validEffects = map[string]bool{"allow": true, "deny": true}

	// tag is DELIBERATELY absent.
	//
	// The enum accepts it and dispatch treats it as fatal: scopePlan cannot
	// express a tag rule on the wire, so it refuses the job — which means one
	// tag rule bricks every job under that policy, permanently, with a
	// scope_violation_halt and an audit event per job. Accepting it here would
	// let an operator do that to themselves through a 201 response.
	//
	// Fail-closed at dispatch is right. Refusing at the write path is what stops
	// it being silent.
	validMatchTypes = map[string]bool{"cidr": true, "hostname": true, "url": true}
)

func (s *Server) addScopeRule(w http.ResponseWriter, r *http.Request) {
	policyID, err := pathUUID(r, "policy_id")
	if err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "policy_id is not a uuid.", err)
		return
	}
	var req ScopeRuleRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"The request body could not be read as this endpoint's schema.", err)
		return
	}
	if !validEffects[req.Effect] || !validMatchTypes[req.MatchType] || req.MatchValue == "" {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"A scope rule needs an effect of allow or deny, a match_type of cidr, hostname or url, and a match_value.", nil)
		return
	}

	// ============================================================================
	// A url rule is stored as its HOST, or it silently matches nothing.
	// ============================================================================
	//
	// Since ADR-044 the target side is reduced to a bare host and the rule side
	// is left as the operator wrote it. A rule written
	// "https://printer.corp.example/setup" therefore falls through to string
	// comparison against "printer.corp.example" and matches nothing — so an
	// operator who EXCLUDED that printer gets an exclusion that protects it from
	// nothing, and a scan that proceeds. That is the "deleted exclusion with no
	// signal" class, arrived at through a supported API call.
	//
	// ADR-040 already decided the rule: scope authorises hosts, and a URL is
	// judged on the host it would reach in both directions. This is where the
	// storage is made to agree with that.
	if req.MatchType == "url" {
		c, err := target.Canonicalise(req.MatchValue)
		if err != nil {
			writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
				"That url does not name a host this system can reach.", err)
			return
		}
		req.MatchValue = c.Value
	}

	// A cidr rule must parse as one. Otherwise scopePlan refuses the job at
	// dispatch — fail-closed, and invisible until a scan stops running.
	if req.MatchType == "cidr" {
		if _, err := netip.ParsePrefix(strings.TrimSpace(req.MatchValue)); err != nil {
			writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
				"A cidr rule's match_value must be a CIDR prefix.", err)
			return
		}
	}

	if req.Precedence == 0 {
		req.Precedence = 100
	}

	tenant, _ := tenantFrom(r.Context())
	var rule *store.ScopeRule
	err = s.db.Write(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		rule, err = (store.Policies{}).AddScopeRule(ctx, c, policyID, store.ScopeRule{
			Effect: store.ScopeRuleEffect(req.Effect), MatchType: store.ScopeMatchType(req.MatchType),
			MatchValue: req.MatchValue, Precedence: req.Precedence,
		})
		if err != nil {
			return err
		}
		id := rule.ID
		return (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
			ActorID: actor(r), ActorType: store.ActorUser,
			Action: "policy.scope_rule_added", ResourceType: "policy_scope_rule", ResourceID: &id,
			Detail: map[string]any{
				"policy_id": policyID.String(), "effect": req.Effect,
				"match_type": req.MatchType, "match_value": req.MatchValue,
			},
		})
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}
	writeJSON(w, r, s.log, http.StatusCreated, ScopeRuleResponse{
		ID: rule.ID.String(), Effect: string(rule.Effect), MatchType: string(rule.MatchType),
		MatchValue: rule.MatchValue, Precedence: rule.Precedence,
	})
}

func (s *Server) listScopeRules(w http.ResponseWriter, r *http.Request) {
	policyID, err := pathUUID(r, "policy_id")
	if err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "policy_id is not a uuid.", err)
		return
	}
	tenant, _ := tenantFrom(r.Context())
	var rules []store.ScopeRule
	err = s.db.Read(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		rules, err = (store.Policies{}).ScopeRules(ctx, c, policyID)
		return err
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}
	out := ScopeRuleListResponse{Rules: make([]ScopeRuleResponse, 0, len(rules))}
	for _, rule := range rules {
		out.Rules = append(out.Rules, ScopeRuleResponse{
			ID: rule.ID.String(), Effect: string(rule.Effect), MatchType: string(rule.MatchType),
			MatchValue: rule.MatchValue, Precedence: rule.Precedence,
		})
	}
	writeJSON(w, r, s.log, http.StatusOK, out)
}

// deleteScopeRule removes one rule.
//
// Audited before it is easy to reach, because deleting a DENY rule widens what
// may be scanned — and the row is gone afterwards, so the event is the only
// record that the exclusion ever existed.
func (s *Server) deleteScopeRule(w http.ResponseWriter, r *http.Request) {
	policyID, err := pathUUID(r, "policy_id")
	if err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "policy_id is not a uuid.", err)
		return
	}
	ruleID, err := pathUUID(r, "rule_id")
	if err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "rule_id is not a uuid.", err)
		return
	}

	tenant, _ := tenantFrom(r.Context())
	err = s.db.Write(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		// Read first, inside the same transaction, so the event can name what
		// was removed. A deleted deny rule that the audit log records only by id
		// tells an investigator nothing about what stopped being excluded.
		rules, err := (store.Policies{}).ScopeRules(ctx, c, policyID)
		if err != nil {
			return err
		}
		var removed *store.ScopeRule
		for i := range rules {
			if rules[i].ID == ruleID {
				removed = &rules[i]
				break
			}
		}
		if err := (store.Policies{}).DeleteScopeRule(ctx, c, policyID, ruleID); err != nil {
			return err
		}
		detail := map[string]any{"policy_id": policyID.String()}
		if removed != nil {
			detail["effect"] = string(removed.Effect)
			detail["match_type"] = string(removed.MatchType)
			detail["match_value"] = removed.MatchValue
		}
		id := ruleID
		return (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
			ActorID: actor(r), ActorType: store.ActorUser,
			Action: "policy.scope_rule_deleted", ResourceType: "policy_scope_rule",
			ResourceID: &id, Detail: detail,
		})
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}
	writeJSON(w, r, s.log, http.StatusNoContent, nil)
}
