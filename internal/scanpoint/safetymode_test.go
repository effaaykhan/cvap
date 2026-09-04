package scanpoint

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
	"github.com/effaaykhan/cvap/internal/enginewire"
)

// Mutations, declared beside the tests that must kill them.
//
// This is the control ADR-021 rests on: safe is the default for every policy, so
// it is the mode most deployments run and the one that must be unable to provoke
// anything. Every mutation below turns it back into a flag the engine is trusted
// to honour.
//
// mutate:subject internal/scanpoint/job.go
// mutate:test    ./internal/scanpoint/ -run TestSafeMode|TestIntrusiveMode|TestAJobWhoseMode|TestTheCorpus|TestEveryProbe
//
// mutate:case    an unrecognised safety mode supplies probes
// mutate:old     if c.GetSafetyMode() == SafetyIntrusive {
// mutate:new     if c.GetSafetyMode() != "safe" {
//
// mutate:subject internal/scanpoint/enginehost.go
//
// mutate:case    a safe-mode job carrying probes is trimmed rather than refused
// mutate:old     if budget.SafetyMode != SafetyIntrusive && len(budget.Probes) > 0 {
// mutate:new     if false {
//
// mutate:subject internal/scanpoint/probes.go
//
// mutate:case    a probe reads without a bound
// mutate:old     ReadBytes: 8 << 10,
// mutate:new     ReadBytes: 0,
//
// Safe mode is enforced by what the engine is HANDED, not by what it is told.
//
// ADR-021 makes safe the default for every policy, so it is the mode most
// deployments run and the one that must be unable to provoke anything. These
// assert the mechanism that makes that true regardless of the engine: the
// runtime holds the probe corpus and hands over an empty one.

// TestSafeModeHandsTheEngineNothingToSend.
func TestSafeModeHandsTheEngineNothingToSend(t *testing.T) {
	for _, mode := range []string{"safe", "", "SAFE", "Intrusive", "unknown-future-mode"} {
		j := &job{
			constraints: &scanpointv1.ScanConstraints{SafetyMode: mode},
			tasks:       []*scanpointv1.Task{{TaskId: "t1", Target: "192.0.2.5"}},
		}
		if got := j.budget().Probes; len(got) != 0 {
			t.Errorf("safety_mode %q handed the engine %d probe(s). Anything that is not "+
				"exactly %q must yield none — an unrecognised mode is not a licence, it is "+
				"a value this build does not understand.", mode, len(got), SafetyIntrusive)
		}
	}
}

// TestIntrusiveModeIsTheOnlyOneThatSupplies. The control has to be a control,
// not a refusal of everything.
func TestIntrusiveModeIsTheOnlyOneThatSupplies(t *testing.T) {
	j := &job{
		constraints: &scanpointv1.ScanConstraints{SafetyMode: SafetyIntrusive},
		tasks:       []*scanpointv1.Task{{TaskId: "t1", Target: "192.0.2.5"}},
	}
	b := j.budget()
	if len(b.Probes) == 0 {
		t.Fatal("an intrusive job was handed no probes; the mode would then do nothing")
	}
	if b.SafetyMode != SafetyIntrusive {
		t.Errorf("SafetyMode = %q, want %q — it travels for provenance even though it does "+
			"not decide anything", b.SafetyMode, SafetyIntrusive)
	}
}

// TestAJobWhoseModeAndProbesDisagreeIsRefused.
//
// Refused rather than trimmed. If the two disagree then something between Core's
// reduction of the policy ceiling and this runtime produced a job whose stated
// mode and actual capability differ, and quietly dropping the probes would leave
// that defect running under a mode label nobody can trust afterwards.
//
// Checked before the process exists, so the job never reaches something that
// could act on it — which is what the h.cmd assertion is for.
func TestAJobWhoseModeAndProbesDisagreeIsRefused(t *testing.T) {
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	h := newEngineHost(log, "/nonexistent", "job-1", []string{"192.0.2.0/24"}, nil)

	err := h.start(t.Context(),
		[]enginewire.Target{{TaskID: "t1", Value: "192.0.2.5"}},
		engineBudget{
			SafetyMode: "safe",
			Probes:     []enginewire.Probe{{Name: "smuggled", Payload: []byte("x")}},
		})

	if err == nil {
		t.Fatal("a safe-mode job carrying probes was accepted")
	}
	if !strings.Contains(err.Error(), "probes supplied") {
		t.Errorf("err = %v, want ErrProbesUnderSafeMode", err)
	}
	if h.cmd != nil {
		t.Error("a process was spawned for a job the runtime refused; the check must happen " +
			"before anything exists that could send the probe")
	}
}

// TestTheCorpusIsNotSharedBetweenJobs.
//
// The runtime hands this to an engine over a pipe, and a shared backing array
// would be a mutable global reachable from the job path.
func TestTheCorpusIsNotSharedBetweenJobs(t *testing.T) {
	a, b := ProbeCorpus(), ProbeCorpus()
	if len(a) == 0 {
		t.Fatal("empty corpus")
	}
	a[0].Payload[0] = 'X'
	if b[0].Payload[0] == 'X' {
		t.Error("two calls to ProbeCorpus share a backing array; one job could rewrite " +
			"what every later job sends")
	}
}

// TestEveryProbeIsBoundedAndCarriesNoTarget.
//
// An engine parses hostile input by design, so an unbounded read is a denial of
// service against your own fleet. And a probe that carried an address would let
// an engine name a host the runtime never authorised, which is target
// construction (ADR-027).
func TestEveryProbeIsBoundedAndCarriesNoTarget(t *testing.T) {
	for _, p := range ProbeCorpus() {
		if p.Name == "" {
			t.Error("a probe with no name cannot be traced from the observation it produced")
		}
		if p.ReadBytes == 0 {
			t.Errorf("probe %q sets no read bound", p.Name)
		}
		if p.ReadBytes > 64<<10 {
			t.Errorf("probe %q may read %d bytes from a hostile host", p.Name, p.ReadBytes)
		}
		body := string(p.Payload)
		for _, addr := range []string{"192.", "10.", "http://", "https://"} {
			if strings.Contains(body, addr) {
				t.Errorf("probe %q embeds what looks like an address (%q). The only address a "+
					"probe may carry is the placeholder the engine substitutes with the "+
					"target the runtime already authorised.", p.Name, addr)
			}
		}
	}
}
