package e2e

import (
	"syscall"
	"testing"
	"time"
)

// TestSigtermSubmitsGatheredResults is the whole-path proof of the graceful-
// shutdown fix, across the process boundary the in-process harness cannot reach
// (TestShutdownWaitsForResultsBeforeExiting proves the seam; this proves the
// binary — F2 established those are different claims).
//
// A real scan point is mid-job when it receives SIGTERM — a rolling restart, a
// deploy, a node drain. It must self-abort, submit what it gathered marked
// incomplete, and only then exit (ADR-026). Before the fix, shutdown() returned
// on j.done before the abort's terminate() enqueued, main saw an empty buffer,
// logged a false "drained", and exited — losing the results every time. This
// asserts they land.
//
// No mutate declaration: main's drain and the runtime's shutdown run inside the
// separately-built cvap-scanpoint binary, which `go test`'s -overlay cannot
// reach (ADR-056). This is the observation; the sabotage lives on the in-process
// harness.
func TestSigtermSubmitsGatheredResults(t *testing.T) {
	h := newSlowHarness(t)
	h.startCore()
	h.startScanPoint()

	// Wait until the job is genuinely running under a lease, then a beat so the
	// engine has gathered something to lose.
	eventually(t, "the job to be leased", 40*time.Second, func() bool {
		_, err := h.currentLease()
		return err == nil
	})
	time.Sleep(1500 * time.Millisecond)
	if h.observationCount() >= taskCount {
		t.Skip("the job finished before SIGTERM could catch it mid-flight; raise slowPerTarget")
	}

	// SIGTERM the scan point process (not the group — the process's own handler
	// stops the engine). This is the signal a deploy or drain sends.
	t.Logf("sending SIGTERM to the scan point mid-job")
	if err := syscall.Kill(h.spCmd.Process.Pid, syscall.SIGTERM); err != nil {
		t.Fatalf("SIGTERM: %v", err)
	}

	// The gathered results must reach Core: a submission for the job, marked
	// incomplete, carrying what the engine produced before the stop. Under the
	// pre-fix code this never arrives — the process exits with the buffer
	// ungathered.
	eventually(t, "the gathered results to be submitted before exit", 30*time.Second, func() bool {
		for _, s := range h.submissions() {
			if s.Incomplete {
				return true
			}
		}
		return false
	})

	var incomplete submissionRow
	for _, s := range h.submissions() {
		if s.Incomplete {
			incomplete = s
		}
	}
	if incomplete.Status == "" {
		t.Fatal("no incomplete submission after SIGTERM; the shutdown lost the gathered results")
	}
	if n := h.observationCount(); n == 0 {
		t.Error("the submission carried no observations; a mid-job SIGTERM must submit what " +
			"was gathered, not an empty record (ADR-026)")
	} else {
		t.Logf("SIGTERM submitted %d gathered observations, marked incomplete", n)
	}
}
