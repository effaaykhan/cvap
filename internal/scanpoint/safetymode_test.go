package scanpoint

import (
	"fmt"
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
// mutate:test    ./internal/scanpoint/ -run TestSafeMode|TestIntrusiveMode|TestAJobWhoseMode|TestTheCorpus|TestEveryProbe|TestAFragileTarget|TestNoProbeReaches|TestThePerScanPoint|TestTheAllocator
//
// The probe-suppression decision moved from budget() into clampToBudget (shared
// with the safety harness so the two enforce the same ceiling); the anchors
// follow it. The tests above still reach it through j.budget().
//
// mutate:case    an unrecognised safety mode supplies probes
// mutate:old     if in.SafetyMode == SafetyIntrusive && !in.AnyFragile {
// mutate:new     if in.SafetyMode != "safe" && !in.AnyFragile {
//
// mutate:case    a fragile target is handed probes anyway
// mutate:old     if in.SafetyMode == SafetyIntrusive && !in.AnyFragile {
// mutate:new     if in.SafetyMode == SafetyIntrusive && (!in.AnyFragile || true) {
//
// The obvious form — dropping `&& !anyFragile` — leaves anyFragile declared and
// unused, so the mutant does not compile and tests nothing. The driver reports
// that rather than counting it as killed, which is the check that caught it.
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
// mutate:old     ReadBytes: 1 << 10,
// mutate:new     ReadBytes: 0,
//
// Anchored on the RDP probe's bound, which is the only 1 KiB one. `ReadBytes:
// 8 << 10` was the original anchor and stopped being unique the moment the
// corpus gained a second HTTP probe; appending a second ReadBytes to another
// probe's payload line was the next attempt and duplicates a struct field, so
// the mutant did not compile. `make mutate` reported both rather than picking
// one, which is the whole reason it reports them.
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

// TestAFragileTargetGetsNoProbesEvenWhenIntrusive.
//
// ADR-024 control 3 is that fragile "suppresses aggressive checks AND caps
// rate". Only the rate half existed: probes were chosen from safety_mode alone
// and Target.Fragile was read by nothing in the engine at all. A packet-capture
// audit measured a HEAD request and a bare newline arriving at a device marked
// fragile — a printer or a PLC, which is what the flag is for.
func TestAFragileTargetGetsNoProbesEvenWhenIntrusive(t *testing.T) {
	fragile := &job{
		constraints: &scanpointv1.ScanConstraints{SafetyMode: SafetyIntrusive},
		tasks: []*scanpointv1.Task{
			{TaskId: "t1", Target: "192.0.2.5"},
			{TaskId: "t2", Target: "192.0.2.6", Fragile: true},
		},
	}
	if got := fragile.budget().Probes; len(got) != 0 {
		t.Errorf("a job containing a fragile target was handed %d probe(s). Suppressing "+
			"aggressive checks is half of what the flag means.", len(got))
	}

	// The control: without a fragile target, an intrusive job still gets them.
	ordinary := &job{
		constraints: &scanpointv1.ScanConstraints{SafetyMode: SafetyIntrusive},
		tasks:       []*scanpointv1.Task{{TaskId: "t1", Target: "192.0.2.5"}},
	}
	if len(ordinary.budget().Probes) == 0 {
		t.Error("an intrusive job with no fragile target was handed no probes")
	}
}

// TestNoProbeReachesAPortWhereBytesAreNotInert.
//
// A bare newline was sent to EVERY open port because the probe declared none.
// 9100 is raw print, where a line is a print job; 502 is Modbus and 102 is S7,
// where unsolicited bytes reach a PLC's protocol stack. Invariant 9: detection
// establishes evidence without achieving impact, and printing a page is impact.
func TestNoProbeReachesAPortWhereBytesAreNotInert(t *testing.T) {
	// Ports where an unsolicited payload does something rather than nothing.
	dangerous := map[uint32]string{
		9100:  "raw print (JetDirect) — a bare line is a print job",
		515:   "LPD",
		631:   "IPP",
		502:   "Modbus",
		102:   "S7 / ISO-TSAP",
		20000: "DNP3",
		47808: "BACnet",
	}

	for _, p := range ProbeCorpus() {
		if len(p.Ports) == 0 {
			t.Errorf("probe %q declares no ports, so it is sent to EVERY open port including "+
				"industrial and printing ones", p.Name)
			continue
		}
		for _, port := range p.Ports {
			if why, bad := dangerous[port]; bad {
				t.Errorf("probe %q targets port %d: %s", p.Name, port, why)
			}
		}
	}
}

// TestThePerScanPointCeilingIsDividedNotHandedOutWhole.
//
// ============================================================================
// ADR-024's 1,000 pps per scan point was read by no code at all.
// ============================================================================
//
// Two of the ADR's three rate ceilings bound: job.budget clamps per-target and
// fragile. The per-scan-point figure was a number in a table — each job built
// its own bucket with nothing subtracting from a shared budget.
//
// Survivable while a scan planned ONE job. Chunking made it reachable in a
// single scan: a /24 plans eight jobs, dispatch hands out five, and a
// packet-capture audit measured 262 pps aggregate from one scan point at a 50
// pps allocation — linear in engine count.
func TestThePerScanPointCeilingIsDividedNotHandedOutWhole(t *testing.T) {
	a := newAllocator(100)

	if got := a.acquire("job-1"); got != 100 {
		t.Errorf("a lone job got %d pps, want the whole ceiling of 100", got)
	}
	if got := a.acquire("job-2"); got != 50 {
		t.Errorf("the second concurrent job got %d pps, want 50 — half of the scan point's "+
			"budget, not another full slice", got)
	}
	if got := a.acquire("job-3"); got != 33 {
		t.Errorf("the third got %d pps, want 33", got)
	}

	// Releasing gives the budget back, or a scan point degrades permanently
	// after a busy period.
	a.release("job-2")
	a.release("job-3")
	if got := a.acquire("job-4"); got != 50 {
		t.Errorf("after two releases a new job got %d pps, want 50 (two holders)", got)
	}
}

// TestTheAllocatorNeverHandsOutZero.
//
// A scan point holding more jobs than its ceiling in pps would otherwise
// allocate nothing and stall every one of them — turning a rate control into a
// deadlock. Core's maxJobsPerPoll is the lever for "too many concurrent jobs";
// this is only the floor that keeps the failure visible rather than silent.
func TestTheAllocatorNeverHandsOutZero(t *testing.T) {
	a := newAllocator(4)
	for i := range 20 {
		if got := a.acquire(fmt.Sprintf("job-%d", i)); got < 1 {
			t.Fatalf("job %d was allocated %d pps", i, got)
		}
	}
	if a.held() != 20 {
		t.Errorf("held() = %d, want 20", a.held())
	}
}

// TestBannerMatchesTravelInSafeModeAndProbesDoNot.
//
// ============================================================================
// The asymmetry between these two lines IS the safe/intrusive distinction.
// ============================================================================
//
// Reading is not sending. A safe job identifies every service that announces
// itself — SSH, SMTP, FTP, POP3, IMAP, Telnet, MySQL — because the bytes have
// already arrived by the time a rule looks at them. Withholding the rules would
// cost that identification and buy no safety whatsoever.
//
// The probes are the withheld half, and they are withheld by being EMPTY rather
// than by a flag the engine is trusted to honour.
func TestBannerMatchesTravelInSafeModeAndProbesDoNot(t *testing.T) {
	safe := &job{
		constraints: &scanpointv1.ScanConstraints{SafetyMode: "safe"},
		tasks:       []*scanpointv1.Task{{TaskId: "t1", Target: "10.10.0.11"}},
	}
	b := safe.budget()
	if len(b.Probes) != 0 {
		t.Errorf("%d probes travelled under a safe job", len(b.Probes))
	}
	if len(b.BannerMatches) == 0 {
		t.Fatal("no banner rules under a safe job: safe mode would identify nothing at all, " +
			"which is not what ADR-021 asks for")
	}
	if b.MaxProbesPerPort == 0 {
		t.Error("no probe-chain cap; zero would be read by the engine as its own default")
	}

	// And a fragile target keeps the rules while losing the probes, because
	// ADR-024 control 3 suppresses aggressive checks and reading is not one.
	fragile := &job{
		constraints: &scanpointv1.ScanConstraints{SafetyMode: SafetyIntrusive},
		tasks:       []*scanpointv1.Task{{TaskId: "t1", Target: "10.10.0.20", Fragile: true}},
	}
	fb := fragile.budget()
	if len(fb.Probes) != 0 {
		t.Errorf("%d probes travelled for a fragile target", len(fb.Probes))
	}
	if len(fb.BannerMatches) == 0 {
		t.Error("a fragile target lost the banner rules, which cost identification and buy nothing")
	}
}
