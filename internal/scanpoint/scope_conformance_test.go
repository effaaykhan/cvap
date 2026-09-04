package scanpoint

import (
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
	"github.com/effaaykhan/cvap/internal/enginewire"
	"github.com/effaaykhan/cvap/internal/scope/scopetest"
	"github.com/effaaykhan/cvap/internal/target"
)

// Mutations, declared beside the tests that must kill them.
//
// The runtime is the site that actually sends packets, and the property worth
// the most here is the one ADR-044 spends a page on: it RE-COMPUTES rather than
// validating. The first mutation is precisely the wrong version — the one that
// passes every test the right one does, unless a test drives a non-canonical
// value.
//
// mutate:subject internal/scanpoint/enginehost.go
// mutate:test    ./internal/scanpoint/ -run TestRuntimeSiteAgreesWithTheSharedTable|TestTheRuntimeRecomputes|TestAnUnauthorisedTargetRefusesTheWholeJob
//
// mutate:case    the runtime validates the form instead of re-computing it
// mutate:old     c, ok := target.Matches(raw)
// mutate:new     c, err := target.Canonicalise(raw); ok := err == nil
//
// mutate:case    a non-canonical target is accepted rather than refused
// mutate:old     return false, "target is not in canonical form: " + raw
// mutate:new     return true, ""
//
// TestRuntimeSiteAgreesWithTheSharedTable is the half that did not exist.
//
// Five comments said it did — in scopetest/cases.go, in scope.go, in
// dispatch/scope.go, in dispatch/scope_conformance_test.go and in this package's
// CLAUDE.md — and two independent reviews found the file missing. The untested
// site was the one ADR-024 added BECAUSE Core cannot be trusted alone, and it is
// the one that actually sends packets.
//
// It drives engineHost.authorise rather than scope.Permits, deliberately. Both
// sites share the matcher, so testing the matcher twice proves nothing; what
// drifts is the CALL. A runtime that stopped passing exclusions, or passed the
// allowlist in both positions, or skipped the check for one class of target
// would compile and pass every other test in this package while quietly
// permitting work Core refuses.
func TestRuntimeSiteAgreesWithTheSharedTable(t *testing.T) {
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))

	for _, tc := range scopetest.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			// The runtime is fed what the WIRE would carry, which since ADR-044
			// is the canonical form Core wrote at planning — not the operator's
			// raw string. A case Core refuses to canonicalise never reaches a
			// scan point at all, and the table records that as a denial.
			canon, err := target.Canonicalise(tc.Target)
			if err != nil {
				if tc.Want {
					t.Fatalf("%q is expected in scope but does not canonicalise: %v", tc.Target, err)
				}
				return
			}

			h := newEngineHost(log, "/nonexistent", "job-1", tc.Allowed, tc.Exclusions)
			got, why := h.authorise(canon.Value)
			if got != tc.Want {
				t.Errorf("runtime verdict for %q (canonical %q) = %v (%s), want %v. Core "+
					"decides the same case in internal/dispatch; a disagreement is a "+
					"target one side permits and the other refuses, and neither "+
					"direction announces itself at runtime.",
					tc.Target, canon.Value, got, why, tc.Want)
			}
		})
	}
}

// TestTheRuntimeRecomputesRatherThanValidating is the property the second
// enforcement site exists for.
//
// Every target below is INSIDE the allowlist and would pass the matcher. Each is
// refused anyway, because the runtime's own canonicalisation of the string does
// not equal the string — which is what a value mutated in transit looks like,
// and what a Core that skipped planning's normalisation produces.
//
// What this site guarantees is narrow and worth stating exactly: nothing reached
// it unnormalised. It cannot catch a canonical string naming the wrong host —
// that is the matcher's job, and the allowlist's. What it catches is the case
// the matcher cannot see, where the string Core decided about and the string
// about to be scanned are not the same string.
func TestTheRuntimeRecomputesRatherThanValidating(t *testing.T) {
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	allowed := []string{"192.0.2.0/24", "corp.example"}

	for _, raw := range []string{
		"192.0.2.5:443",          // a port survived planning
		"[192.0.2.5]",            // brackets survived planning
		"192.0.2.5.",             // the root label survived planning
		"::ffff:192.0.2.5",       // an unmapped form survived planning
		"https://corp.example/x", // a URL survived planning
		"CORP.example",           // case survived planning
		" 192.0.2.5",             // whitespace was reintroduced on the wire
	} {
		h := newEngineHost(log, "/nonexistent", "job-1", allowed, nil)
		if ok, _ := h.authorise(raw); ok {
			t.Errorf("the runtime accepted %q, which is not its own canonical form of "+
				"itself. Accepting it means the second site validated Core's answer "+
				"instead of computing its own, and a canonical form of the WRONG host "+
				"is exactly what a bug in Core's canonicalisation produces.", raw)
		}
	}

	// The control: an in-scope target in the form planning actually writes.
	h := newEngineHost(log, "/nonexistent", "job-1", allowed, nil)
	if ok, why := h.authorise("192.0.2.5"); !ok {
		t.Errorf("the runtime refused a canonical in-scope target: %s", why)
	}
}

// TestAnUnauthorisedTargetRefusesTheWholeJob.
//
// Not trimmed. A runtime that dropped the offending target and scanned the rest
// would turn a disagreement between the two enforcement sites into a silent
// partial scan — and that disagreement is the single most important thing an
// operator could be told, because it means Core planned work this scan point was
// not willing to do.
func TestAnUnauthorisedTargetRefusesTheWholeJob(t *testing.T) {
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	h := newEngineHost(log, "/nonexistent", "job-1", []string{"192.0.2.0/24"}, nil)

	err := h.start(t.Context(), []enginewire.Target{
		{TaskID: "t1", Value: "192.0.2.5"},
		{TaskID: "t2", Value: "198.51.100.9"}, // outside the allowlist
	}, engineBudget{})

	if err == nil {
		t.Fatal("a job containing an unauthorised target was accepted")
	}
	if !errors.Is(err, ErrOutOfScope) {
		t.Errorf("err = %v, want ErrOutOfScope", err)
	}
	if h.cmd != nil {
		t.Error("a process was spawned for a job the runtime refused; a target the " +
			"runtime will not permit must never be named to something that could act on it")
	}
}

// TestAStopBeforeStartRefusesTheSpawn is the race two reviews reproduced.
//
// receiveLoop delivers messages back to back, so a CancelJob or KillSwitch
// immediately after an assignment reached the terminal path before the job's
// goroutine reached the spawn. The runtime reported the job stopped,
// acknowledged the cancellation to Core, and then started the engine — which
// then ran outside the job table, unreachable by a second cancel, by the kill
// switch or by the lease watchdog.
func TestAStopBeforeStartRefusesTheSpawn(t *testing.T) {
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	h := newEngineHost(log, "/bin/sh", "job-1", []string{"192.0.2.0/24"}, nil)

	// The stop arrives first, with no process yet — stop() records the request
	// precisely so start() can see it.
	h.stop(time.Millisecond)

	err := h.start(t.Context(), []enginewire.Target{{TaskID: "t1", Value: "192.0.2.5"}}, engineBudget{})
	if !errors.Is(err, errStopBeforeStart) {
		t.Fatalf("start after a stop = %v, want errStopBeforeStart", err)
	}
	if h.cmd != nil {
		t.Error("an engine was spawned after the job had already been reported stopped")
	}
}

// TestTheGraceIsBoundedAtTheReceiver. CancelJob.grace_ms arrives from the
// network and ADR-024's 10 s propagation bound is "not adjustable"; the receiver
// is the only place that can hold it.
func TestTheGraceIsBoundedAtTheReceiver(t *testing.T) {
	if MaxStopGrace >= 10*time.Second {
		t.Errorf("MaxStopGrace is %v; ADR-024 bounds kill propagation at 10s and the "+
			"SIGKILL has to land inside it", MaxStopGrace)
	}
}

// TestPlatformCeilingsAreAppliedAtTheRuntime is ADR-024 control 2's second site.
//
// job.budget forwarded whatever Core sent, so a Core that said
// max_rate_per_target = 100000 got 100000. The ADR rejected single-site
// enforcement for rate exactly as it did for targets.
func TestPlatformCeilingsAreAppliedAtTheRuntime(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		sent                     *scanpointv1.ScanConstraints
		fragile                  bool
		wantRate, wantConcurrent uint32
	}{
		{
			name:     "a policy that lowers is honoured",
			sent:     &scanpointv1.ScanConstraints{MaxRatePerTarget: 5, MaxConcurrentPerTarget: 2},
			wantRate: 5, wantConcurrent: 2,
		},
		{
			name:     "a Core that tries to raise is clamped",
			sent:     &scanpointv1.ScanConstraints{MaxRatePerTarget: 100000, MaxConcurrentPerTarget: 5000},
			wantRate: PlatformMaxRatePerTarget, wantConcurrent: PlatformMaxConcurrentPerTarget,
		},
		{
			name:     "an unset ceiling is the platform default, not unlimited",
			sent:     &scanpointv1.ScanConstraints{},
			wantRate: PlatformMaxRatePerTarget, wantConcurrent: PlatformMaxConcurrentPerTarget,
		},
		{
			// ADR-024 control 3: fragile caps rate REGARDLESS of policy, so the
			// runtime holds the number and applies it even when Core sends 0.
			name: "fragile caps the rate even when Core sends no fragile value",
			// Fragile SERIALISES as well as slows. A packet capture at a 10 pps
			// fragile budget showed a mean of 9.88 and a worst second of 18,
			// because the packets of one TCP-plus-TLS exchange are atomic and the
			// peak is two exchanges landing together. Connection count is the
			// other lever ADR-024 control 3 is about.
			sent:     &scanpointv1.ScanConstraints{MaxRatePerTarget: 50},
			fragile:  true,
			wantRate: PlatformFragileRatePPS, wantConcurrent: PlatformFragileMaxConcurrent,
		},
		{
			name:     "and a lower fragile value from Core is honoured",
			sent:     &scanpointv1.ScanConstraints{MaxRatePerTarget: 50, FragileRatePps: 3},
			fragile:  true,
			wantRate: 3, wantConcurrent: PlatformFragileMaxConcurrent,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			j := &job{
				constraints: tc.sent,
				tasks:       []*scanpointv1.Task{{TaskId: "t1", Target: "192.0.2.5", Fragile: tc.fragile}},
			}
			b := j.budget()
			if b.RatePPS != tc.wantRate {
				t.Errorf("rate = %d, want %d", b.RatePPS, tc.wantRate)
			}
			if b.MaxConcurrentPerTarget != tc.wantConcurrent {
				t.Errorf("concurrency = %d, want %d", b.MaxConcurrentPerTarget, tc.wantConcurrent)
			}
		})
	}
}
