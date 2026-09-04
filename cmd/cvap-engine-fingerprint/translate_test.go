package main

import (
	"reflect"
	"testing"
	"time"

	"github.com/effaaykhan/cvap/internal/engines/fingerprint"
	"github.com/effaaykhan/cvap/internal/enginewire"
)

// TestEveryProbeFieldSurvivesTranslation.
//
// ============================================================================
// A translation that drops a field is invisible by construction.
// ============================================================================
//
// Both sides compile, and the receiver simply sees a zero value. `Kind` was
// dropped here for exactly as long as it took to point the engine at the lab and
// notice a capture with one connection in it where there should have been two:
// an ssh_hostkey probe arrived as a payload probe with no payload, which the
// engine then withheld, so the one identity key most Linux hosts can offer was
// silently never collected.
//
// Reflection rather than a hand-written field list, because a hand-written list
// is the same thing that failed: it needs updating by whoever adds the field,
// and whoever adds the field is the person who just forgot.
func TestEveryProbeFieldSurvivesTranslation(t *testing.T) {
	in := enginewire.Probe{
		Name:      "everything",
		Kind:      enginewire.ProbeKindSSHHostKey,
		Ports:     []uint32{22},
		Payload:   []byte("x"),
		ReadBytes: 4096,
		TLS:       true,
		Rarity:    3,
		Matches:   []enginewire.Match{{Pattern: "^x", Service: "ssh", Confidence: 0.9}},
	}

	// Every field of the wire type must be non-zero here, or this test passes
	// over the one that was forgotten.
	v := reflect.ValueOf(in)
	for i := range v.NumField() {
		if v.Field(i).IsZero() {
			t.Fatalf("enginewire.Probe.%s is zero in this fixture, so translation of it is "+
				"not checked. Set it.", v.Type().Field(i).Name)
		}
	}

	got := toProbes([]enginewire.Probe{in})
	if len(got) != 1 {
		t.Fatalf("translated %d probes, want 1", len(got))
	}
	g := reflect.ValueOf(got[0])
	for i := range g.NumField() {
		if g.Field(i).IsZero() {
			t.Errorf("fingerprint.Probe.%s is zero after translation; the wire value was "+
				"dropped", g.Type().Field(i).Name)
		}
	}
}

// TestEveryMatchFieldSurvivesTranslation. Same argument, one type down.
func TestEveryMatchFieldSurvivesTranslation(t *testing.T) {
	in := enginewire.Match{
		Pattern: "^x", Service: "ssh", Product: "OpenSSH", Soft: true,
		Confidence: 0.9, OSHint: "Ubuntu", Ports: []uint32{22},
	}
	v := reflect.ValueOf(in)
	for i := range v.NumField() {
		if v.Field(i).IsZero() {
			t.Fatalf("enginewire.Match.%s is zero in this fixture; set it", v.Type().Field(i).Name)
		}
	}

	got := toMatches([]enginewire.Match{in})
	if len(got) != 1 {
		t.Fatalf("translated %d matches, want 1", len(got))
	}
	g := reflect.ValueOf(got[0])
	for i := range g.NumField() {
		// re is filled by the engine at compile time, not by translation.
		if g.Type().Field(i).Name == "re" {
			continue
		}
		if g.Field(i).IsZero() {
			t.Errorf("fingerprint.Match.%s is zero after translation", g.Type().Field(i).Name)
		}
	}
}

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
	in := fingerprint.Observation{
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
			t.Fatalf("fingerprint.Observation.%s is zero in this fixture, so translation of it is "+
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
