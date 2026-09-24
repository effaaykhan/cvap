package correlate

import (
	"encoding/json"
	"testing"

	"github.com/effaaykhan/cvap/internal/store"
)

// ADR-103 decision 2: a seen-only port is NOT visible to the rule engine.
//
// This asserts the MECHANISM, and it exists because the end-to-end version does
// not. Seeding port observations and checking no finding appears passes whether
// or not the boundary is there: a discovery `port` payload carries no product,
// service or version, so the rules match nothing even when handed one. Removing
// the type filter in serviceObservations left that test green — the outcome is
// masked by the payload's shape, so only the filter itself can be pinned.
//
// The measurement behind decision 2: ports 2000 and 5060 answered on 19 of 19
// hosts of a real /24 pair — one middlebox replying for the range. Those rows
// are now durable. This is the line that keeps them out of the rules.
// mutate:subject internal/correlate/findings.go
// mutate:test    ./internal/correlate/ -run TestPortObservationsNeverReachTheRuleEngine
//
// mutate:case    a port observation is handed to the rule engine as if it were a service
// mutate:old     if o.Type != "service" {
// mutate:new     if o.Type != "service" && o.Type != "port" {
func TestPortObservationsNeverReachTheRuleEngine(t *testing.T) {
	// A port observation carrying a payload that WOULD satisfy a rule if the
	// filter let it through. The fields are a service payload's; only the
	// observation's TYPE says it is not one.
	body, err := json.Marshal(map[string]any{
		"address": "10.10.0.9", "port": 22, "protocol": "tcp",
		"service": "ssh", "product": "OpenSSH", "version": "7.4",
		"method": "banner", "solicited": true, "safety_mode": "safe",
	})
	if err != nil {
		t.Fatal(err)
	}

	h := host{address: "10.10.0.9", obs: []store.Observation{
		{Type: store.ObsPort, Payload: body},
	}}
	if got := serviceObservations(h); len(got) != 0 {
		t.Fatalf("a port observation reached the rule engine's input (%d rows). "+
			"Its payload here is deliberately rule-shaped, so the TYPE filter is "+
			"the only thing between a middlebox's 19-of-19 answer and nineteen "+
			"findings (ADR-103 decision 2).", len(got))
	}

	// The control: the same payload as a service observation DOES reach the
	// rules, so this is not passing because serviceObservations returns nothing
	// for everything.
	h.obs = []store.Observation{{Type: store.ObsService, Payload: body}}
	if got := serviceObservations(h); len(got) != 1 {
		t.Fatalf("a service observation produced %d rule inputs, want 1 — "+
			"the assertion above proves nothing if nothing ever gets through", len(got))
	}
}
