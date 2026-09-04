package rules

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestOneEndpointFromTwoZonesGroupsToOneResultWithTwoZones is ADR-010 at the
// engine level: the same endpoint seen from two vantage points is one result
// carrying both zones, never two results.
func TestOneEndpointFromTwoZonesGroupsToOneResultWithTwoZones(t *testing.T) {
	rule := Rule{ID: uuid.New(), Name: "plaintext-telnet", Evaluator: "plaintext.service",
		Params: []byte(`{"services":["telnet"]}`), Severity: "high", Confidence: 0.9, Version: 1}

	zoneA, zoneB := uuid.New(), uuid.New()
	mk := func(zone uuid.UUID, at time.Time) ServiceObservation {
		return ServiceObservation{ObservationID: uuid.New(), ZoneID: zone, ObservedAt: at,
			Address: "10.10.0.51", Port: 23, Protocol: "tcp", Service: "telnet"}
	}
	sub := Subject{AssetID: uuid.New(), ZoneType: func(uuid.UUID) string { return "internal" },
		Services: []ServiceObservation{
			mk(zoneA, time.Unix(100, 0)),
			mk(zoneB, time.Unix(200, 0)),
		}}

	res, err := Evaluate([]Rule{rule}, sub, time.Unix(300, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("%d results, want 1 (one finding, two exposures)", len(res))
	}
	if len(res[0].Zones) != 2 {
		t.Errorf("%d zones on the result, want 2", len(res[0].Zones))
	}
}

// TestLoadRefusesAnUnknownEvaluator: a rule naming an evaluator this build does
// not implement is refused, not skipped. A skipped rule silently never fires.
func TestLoadRefusesAnUnknownEvaluator(t *testing.T) {
	_, err := Load([]Rule{
		{Name: "future-rule", Evaluator: "quantum.entanglement", Confidence: 0.9},
	}, time.Unix(0, 0))
	if err == nil {
		t.Fatal("a rule with an unimplemented evaluator loaded")
	}
}

// TestLoadRefusesAMalformedThreshold surfaces a bad parameter at load, not on
// the first asset it would be evaluated against.
func TestLoadRefusesAMalformedThreshold(t *testing.T) {
	_, err := Load([]Rule{
		{Name: "bad-warn", Evaluator: "tls.expiring", Confidence: 0.9,
			Params: []byte(`{"warn_days": -5}`)},
	}, time.Unix(0, 0))
	if err == nil {
		t.Fatal("a rule with a negative warn_days loaded")
	}
}
