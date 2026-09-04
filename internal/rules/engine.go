package rules

import (
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
)

// The engine: rules × subject → findings, grouped the way ADR-010 says.

// Result is one finding after grouping: the same issue on the same endpoint
// seen from several vantage points is ONE finding with several exposures
// (ADR-008, ADR-010), never one finding per zone.
type Result struct {
	Finding  Finding
	DedupKey string
	Locator  string

	// Zones that observed this endpoint, in the order first seen. Each becomes
	// a finding_exposure row. Deduplicated: the same zone scanning twice is one
	// vantage point, not two.
	Zones []uuid.UUID
}

// Load validates rule rows against the vocabulary.
//
// ============================================================================
// A rule naming an evaluator this build does not implement is REFUSED, and the
// refusal is an error rather than a skip.
// ============================================================================
//
// A rule that silently never fires is the failure a rule engine is for: the
// row is there, the pack says it is active, and no finding ever raises. Same
// direction the fingerprint pack takes with an unknown probe kind (ADR-049).
// The evaluator's parameters are decoded here as well, so a malformed threshold
// fails at load rather than on the first asset it is evaluated against.
func Load(rows []Rule, now time.Time) ([]Rule, error) {
	var out []Rule
	for _, r := range rows {
		ev, ok := Evaluators[r.Evaluator]
		if !ok {
			return nil, fmt.Errorf("rule %q names evaluator %q, which this build does not implement",
				r.Name, r.Evaluator)
		}
		if r.Confidence <= 0 || r.Confidence > 1 {
			return nil, fmt.Errorf("rule %q has confidence %v, which is not in (0,1]", r.Name, r.Confidence)
		}
		// Evaluate against an empty subject to surface a parameter error now.
		// Evaluators validate their params before looking at services, so an
		// empty subject is enough to reach every decode.
		if _, err := ev(r, Subject{ZoneType: func(uuid.UUID) string { return "" }}, now); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// Evaluate runs every rule over the subject and groups what they raise.
//
// Pure. The caller supplies `now`, so a replay over last year's observations
// reaches last year's answer — which is what makes a rule correction
// retroactive (ADR-013) rather than merely prospective.
func Evaluate(rulesIn []Rule, s Subject, now time.Time) ([]Result, error) {
	if s.ZoneType == nil {
		s.ZoneType = func(uuid.UUID) string { return "" }
	}

	byKey := map[string]*Result{}
	var order []string

	for _, r := range rulesIn {
		ev, ok := Evaluators[r.Evaluator]
		if !ok {
			// Load refuses these; reaching here means a caller skipped Load.
			// Refused again rather than ignored, for the same reason.
			return nil, fmt.Errorf("rule %q names evaluator %q, which this build does not implement",
				r.Name, r.Evaluator)
		}
		raised, err := ev(r, s, now)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", r.Name, err)
		}
		for _, f := range raised {
			key := NetworkDedupKey(s.AssetID, f.Service.Port, f.Service.Protocol, r.Name)
			res, seen := byKey[key]
			if !seen {
				res = &Result{
					Finding:  f,
					DedupKey: key,
					Locator:  Locator(f.Service.Port, f.Service.Protocol),
				}
				byKey[key] = res
				order = append(order, key)
			}
			if !containsZone(res.Zones, f.Service.ZoneID) && f.Service.ZoneID != uuid.Nil {
				res.Zones = append(res.Zones, f.Service.ZoneID)
			}
			// The most recent observation is the one the finding quotes: if the
			// certificate rotated between two scans in the window, the newer
			// evidence is what an operator will find when they look.
			if f.Service.ObservedAt.After(res.Finding.Service.ObservedAt) {
				res.Finding = f
			}
		}
	}

	out := make([]Result, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	return out, nil
}

// Endpoints lists every endpoint the subject re-observed, for the lifecycle.
//
// A finding on an endpoint in this list that was NOT raised this pass has been
// remediated. A finding on an endpoint absent from this list has merely not
// been looked at, and closing it would be reporting a fix nobody made.
func Endpoints(s Subject) []string {
	seen := map[string]bool{}
	var out []string
	for _, svc := range s.Services {
		l := Locator(svc.Port, svc.Protocol)
		if !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	sort.Strings(out)
	return out
}

func containsZone(zones []uuid.UUID, z uuid.UUID) bool {
	for _, x := range zones {
		if x == z {
			return true
		}
	}
	return false
}
