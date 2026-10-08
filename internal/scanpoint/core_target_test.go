package scanpoint

import (
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/effaaykhan/cvap/internal/enginewire"
	"github.com/effaaykhan/cvap/internal/target"
)

func testCore(t *testing.T) target.CoreEndpoints {
	t.Helper()
	c, err := target.NewCoreEndpoints(t.Context(), []string{"192.0.2.10:8443", "192.0.2.10:8444"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestTheRuntimeRefusesACoreEndpointWhateverTheScopeSays: ADR-110's site-two
// half. The allowlist below authorises the whole /24 Core sits in, and Core is
// still refused; its neighbours are not.
//
// mutate:subject internal/scanpoint/enginehost.go
// mutate:test    ./internal/scanpoint/ -run TestTheRuntimeRefusesACoreEndpointWhateverTheScopeSays|TestAJobNamingCoreIsRefusedBeforeAnyEngineExists|TestTheSafetyHarnessRefusesCoreThroughTheSamePath
// mutate:case    the runtime consults only the scope rules, so a job naming a Core endpoint spawns an engine
// mutate:old     if h.core.Contains(c) {
// mutate:new     if false && h.core.Contains(c) {
func TestTheRuntimeRefusesACoreEndpointWhateverTheScopeSays(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Every target below is authorised by these rules, so a refusal can only
	// come from the Core check - proved by the control host, which has no Core
	// set and must permit all of them. Only addresses: scope never authorises a
	// range target at this site (planning expands ranges to addresses), so a
	// range case here could not have a control; target.CoreEndpoints' own tests
	// cover ranges that sweep Core.
	allowed := []string{"192.0.2.0/24"}
	control := newEngineHost(log, "/nonexistent", "job-0", allowed, nil, target.CoreEndpoints{})
	h := newEngineHost(log, "/nonexistent", "job-1", allowed, nil, testCore(t))
	for _, c := range []struct {
		target string
		ok     bool
	}{
		{"192.0.2.10", false},
		{"192.0.2.9", true},
		{"192.0.2.11", true},
	} {
		if ok, why := control.authorise(c.target); !ok {
			t.Fatalf("control: scope itself refuses %s (%s); the case proves nothing", c.target, why)
		}
		ok, why := h.authorise(c.target)
		if ok != c.ok {
			t.Errorf("authorise(%s) = %v (%s), want %v", c.target, ok, why, c.ok)
		}
	}
}

// TestAJobNamingCoreIsRefusedBeforeAnyEngineExists: the whole job is refused
// with ErrOutOfScope, as for any out-of-scope target, and no process is created
// - the binary does not exist, so a spawn attempt would fail differently.
func TestAJobNamingCoreIsRefusedBeforeAnyEngineExists(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := newEngineHost(log, "/nonexistent", "job-1", []string{"192.0.2.0/24"}, nil, testCore(t))
	err := h.authoriseAll([]enginewire.Target{{TaskID: "a", Value: "192.0.2.11"}, {TaskID: "b", Value: "192.0.2.10"}})
	if !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("authoriseAll = %v, want ErrOutOfScope", err)
	}
	if h.cmd != nil {
		t.Error("an engine process was created for a job that names Core")
	}
}

// TestTheSafetyHarnessRefusesCoreThroughTheSamePath: the gate drives this
// refusal onto a wire through SafetyDrive, so it must go through the same
// engineHost check rather than one of its own.
func TestTheSafetyHarnessRefusesCoreThroughTheSamePath(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	res, err := SafetyDrive(t.Context(), log, "/nonexistent", SafetyJob{
		JobID: "safety-core", Allowed: []string{"192.0.2.0/24"},
		Targets: []enginewire.Target{{TaskID: "t", Value: "192.0.2.10"}},
		RatePPS: 10, ConnectTimeoutMS: 500, MaxConcurrentPerTarget: 1, SafetyMode: "safe",
		CoreEndpoints: []string{"192.0.2.10:8444"},
	})
	if err != nil {
		t.Fatalf("SafetyDrive: %v", err)
	}
	if !res.Refused {
		t.Errorf("a job naming Core was not refused: %+v", res)
	}
}

// TestWithNoCoreSetNothingExtraIsRefused: the zero set (tests, and only tests,
// construct one) changes no other verdict.
func TestWithNoCoreSetNothingExtraIsRefused(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := newEngineHost(log, "/nonexistent", "job-1", []string{"192.0.2.0/24"}, nil, target.CoreEndpoints{})
	if ok, why := h.authorise("192.0.2.10"); !ok {
		t.Errorf("refused without a Core set: %s", why)
	}
}

// TestCoreEndpointsAreBuiltFromEnrollmentAndRefuseAnEmptySet: the runtime's set
// is the configured enrollment endpoint plus what enrollment returned, and a
// scan point with nothing concrete to refuse does not get a set at all.
func TestCoreEndpointsAreBuiltFromEnrollmentAndRefuseAnEmptySet(t *testing.T) {
	c, err := CoreEndpoints(t.Context(), Config{EnrollEndpoint: "192.0.2.10:8443"},
		&Identity{DispatchAddr: "192.0.2.20:8444", IngestAddr: "192.0.2.20:8444", RulePacksAddr: "192.0.2.21:8444"})
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"192.0.2.10", "192.0.2.20", "192.0.2.21"} {
		if !c.Contains(mustCanonical(t, a)) {
			t.Errorf("%s (a Core endpoint) is not in the set", a)
		}
	}
	if _, err := CoreEndpoints(t.Context(), Config{EnrollEndpoint: ":8443"}, &Identity{DispatchAddr: "0.0.0.0:8444"}); err == nil {
		t.Error("a scan point with only listen addresses got a Core set instead of an error")
	}
}

func mustCanonical(t *testing.T, raw string) target.Canonical {
	t.Helper()
	c, ok := target.Matches(raw)
	if !ok {
		t.Fatalf("%q is not canonical", raw)
	}
	return c
}
