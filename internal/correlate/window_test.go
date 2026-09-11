package correlate_test

import (
	"testing"

	"github.com/effaaykhan/cvap/internal/correlate"
	"github.com/effaaykhan/cvap/internal/store"
)

// The ADR-091 trust root rests on the address relationship: a sighting counts
// for as long as the address it was seen at is evidence of the same host
// (ADR-094). The two windows are declared in two packages that must not import
// each other's reasoning, so their equality is asserted rather than assumed.
func TestASightingLivesExactlyAsLongAsAnAddress(t *testing.T) {
	if store.SightingWindow != correlate.AddressWindow {
		t.Fatalf("store.SightingWindow = %s, correlate.AddressWindow = %s; a trust root must not outlive the address relationship it rests on",
			store.SightingWindow, correlate.AddressWindow)
	}
}
