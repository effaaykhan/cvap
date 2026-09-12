package correlate

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/rules"
	"github.com/effaaykhan/cvap/internal/store"
)

// The finding pipeline: after an asset is resolved, decide what its services
// mean (ADR-013, evidence-based, at Core).
//
// ============================================================================
// Evaluation runs right after correlation, over the asset just touched, in the
// SAME transaction that wrote it.
// ============================================================================
//
// The moment the derived model changed is the moment to re-judge it, and the
// observation's zone — which exposure is (ADR-008) — is in hand here and nowhere
// downstream. Same transaction because a finding written against an asset whose
// resolution rolled back would reference a row that never committed.
//
// A rule correction that must re-judge history is a different entry point
// (rules.Evaluate over ListByAsset), and it lands with pack import — named in
// ADR-050, not built here.

// evaluateFindings runs the loaded rules over one resolved host and writes what
// they raise. Called from resolveHost, inside its transaction.
func (c *Correlator) evaluateFindings(ctx context.Context, conn *store.Conn, assetID uuid.UUID, env string, h host, zoneType func(uuid.UUID) string, now time.Time) error {
	if len(c.rules) == 0 {
		return nil // no rules loaded; nothing to evaluate
	}

	subject := rules.Subject{
		AssetID:     assetID,
		Environment: env,
		ZoneType:    zoneType,
		Services:    serviceObservations(h),
	}
	if len(subject.Services) == 0 {
		return nil
	}

	results, err := rules.Evaluate(c.rules, subject, now)
	if err != nil {
		return err
	}

	raised := map[string]bool{} // locators that fired, for the lifecycle
	for _, res := range results {
		id, reopened, err := (store.Findings{}).Upsert(ctx, conn, store.Finding{
			AssetID:    assetID,
			RuleID:     res.Finding.Rule.ID,
			DedupKey:   res.DedupKey,
			Locator:    res.Locator,
			Severity:   res.Finding.Rule.Severity,
			Confidence: res.Finding.Confidence,
			Summary:    res.Finding.Summary,
		}, now)
		if err != nil {
			return err
		}
		raised[res.Locator] = true

		if reopened {
			// The issue an operator marked fixed is back. A history row records
			// the transition; migration 0011 forbids deleting one.
			if err := (store.Findings{}).RecordTransition(ctx, conn, id,
				"remediated", "open", "re-detected on a later scan: "+res.Finding.Summary, now); err != nil {
				return err
			}
		}

		if err := (store.Findings{}).SetExposure(ctx, conn, id, res.Zones, now); err != nil {
			return err
		}
		if err := (store.Findings{}).ReplaceEvidence(ctx, conn, id,
			[]store.FindingEvidence{{
				ObservationID: res.Finding.Service.ObservationID,
				Type:          evidenceType(res.Finding),
				Data:          withProvenance(res.Finding),
				CapturedAt:    res.Finding.Service.ObservedAt,
			}}); err != nil {
			return err
		}
	}

	// Lifecycle: an open finding on an endpoint that was RE-OBSERVED this pass
	// and did NOT fire has been remediated. An endpoint that was not scanned is
	// absent from this list, and its findings are left alone — closing them would
	// report a fix nobody made.
	return c.closeRemediated(ctx, conn, assetID, subject, raised, now)
}

func (c *Correlator) closeRemediated(ctx context.Context, conn *store.Conn, assetID uuid.UUID, subject rules.Subject, raised map[string]bool, now time.Time) error {
	observed := rules.Endpoints(subject)
	open, err := (store.Findings{}).OpenForAssetLocators(ctx, conn, assetID, observed)
	if err != nil {
		return err
	}
	for _, f := range open {
		if raised[f.Locator] {
			continue // still firing
		}
		if err := (store.Findings{}).MarkRemediated(ctx, conn, f.ID, now); err != nil {
			return err
		}
		if err := (store.Findings{}).RecordTransition(ctx, conn, f.ID,
			f.Status, "remediated",
			"endpoint "+f.Locator+" was re-observed and the rule no longer fires", now); err != nil {
			return err
		}
	}
	return nil
}

// serviceObservations decodes this host's `service` observations into the shape
// the rule engine reads.
//
// From the OBSERVATIONS, not the derived services row, so each carries the zone
// it was seen from and the raw evidence excerpt (ADR-008, and the rules engine's
// Subject doc).
func serviceObservations(h host) []rules.ServiceObservation {
	var out []rules.ServiceObservation
	for _, o := range h.obs {
		if o.Type != "service" {
			continue
		}
		var p serviceRulePayload
		if err := json.Unmarshal(o.Payload, &p); err != nil {
			continue
		}
		if p.Port == 0 {
			continue
		}
		so := rules.ServiceObservation{
			ObservationID: o.ID,
			ZoneID:        o.ZoneID,
			ObservedAt:    o.ObservedAt,
			Address:       p.Address,
			Port:          int(p.Port),
			Protocol:      orDefault(p.Protocol, "tcp"),
			Service:       p.Service,
			Product:       p.Product,
			Version:       p.Version,
			Confidence:    confidenceOf(o),
			Method:        p.Method,
			Evidence:      p.Evidence,
		}
		if len(p.TLS) > 0 {
			var t rules.TLSEvidence
			if err := json.Unmarshal(p.TLS, &t); err == nil {
				so.TLS = &t
			}
		}
		if len(p.SSH) > 0 {
			var sh rules.SSHEvidence
			if err := json.Unmarshal(p.SSH, &sh); err == nil {
				so.SSH = &sh
			}
		}
		out = append(out, so)
	}
	return out
}

// serviceRulePayload is what the rule engine reads from a `service` observation.
// A superset of the identity payload in evidence.go — it adds the evidence
// excerpt and the fields the rules quote.
type serviceRulePayload struct {
	Address  string          `json:"address"`
	Port     uint16          `json:"port"`
	Protocol string          `json:"protocol"`
	Service  string          `json:"service"`
	Product  string          `json:"product"`
	Version  string          `json:"version"`
	Method   string          `json:"method"`
	Evidence string          `json:"evidence"`
	TLS      json.RawMessage `json:"tls"`
	SSH      json.RawMessage `json:"ssh"`
}

// evidenceType maps a finding to the evidence_type enum. Everything this session
// raises is read from a banner/certificate/header response, which is `response`
// — `banner` is for the volunteered greeting specifically, and the finer
// distinctions (config_value, code_span) belong to sources that do not exist yet.
func evidenceType(f rules.Finding) string {
	return "response"
}

// withProvenance adds the rule and the summary to the evidence blob, so the
// stored evidence answers "why does the system believe this" on its own —
// which is the first question an analyst asks about a finding they doubt
// (ADR-006).
func withProvenance(f rules.Finding) map[string]any {
	ev := map[string]any{
		"rule":         f.Rule.Name,
		"rule_version": f.Rule.Version,
		"summary":      f.Summary,
		"cwe":          f.Rule.CWE,
	}
	for k, v := range f.Evidence {
		ev[k] = v
	}
	return ev
}

// confidenceOf is the observation's own confidence, or -1 when the row carries
// none (a hand-built row; ingest always stores one). Absent and zero are
// different facts: zero is the weakest possible claim and composes as zero,
// absent composes at the pass-through. The first cut folded 0 into "absent"
// and promoted the weakest claim to the strongest.
func confidenceOf(o store.Observation) float64 {
	if o.Confidence == nil {
		return -1
	}
	return *o.Confidence
}
