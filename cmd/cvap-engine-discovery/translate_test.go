package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/effaaykhan/cvap/internal/engines/discovery"
)

// TestEveryObservationFieldSurvivesTranslation.
//
// ============================================================================
// The return path. Worse to get wrong than the outbound one.
// ============================================================================
//
// `enginewire.Probe.Kind` was dropped translating INTO the engine, and nothing
// noticed: both sides compiled and the receiver saw a zero value. The same
// exposure exists coming back, where the cost is higher — a field lost on the
// way out means a probe that never ran, and a field lost on the way back means
// evidence that was gathered, paid for in packets, and then discarded while the
// observation still looks complete.
//
// Reflection rather than a hand-written field list, because a hand-written list
// is the same thing that failed: it needs updating by whoever adds the field,
// and whoever adds the field is the person who just forgot.
func TestEveryObservationFieldSurvivesTranslation(t *testing.T) {
	in := discovery.Observation{
		ObservationID: "01234567-89ab-4def-8123-456789abcdef",
		TaskID:        "t1",
		Type:          "service",
		Payload:       []byte(`{"address":"10.10.0.14"}`),
		Confidence:    0.95,
		ObservedAt:    time.Now().UTC(),
	}

	v := reflect.ValueOf(in)
	for i := range v.NumField() {
		if v.Field(i).IsZero() {
			t.Fatalf("discovery.Observation.%s is zero in this fixture, so translation of it is "+
				"not checked. Set it.", v.Type().Field(i).Name)
		}
	}

	got := toObservation(in)
	if got == nil {
		t.Fatal("translated to nil")
	}
	g := reflect.ValueOf(*got)
	for i := range g.NumField() {
		if g.Field(i).IsZero() {
			t.Errorf("enginewire.Observation.%s is zero after translation; the engine's "+
				"value was dropped", g.Type().Field(i).Name)
		}
	}
}
