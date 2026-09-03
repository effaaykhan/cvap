package e2e

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/effaaykhan/cvap/internal/store"
)

// TestEnrollThroughToResults is the whole loop, over two processes and real TLS.
//
// A scan point with no identity enrols, receives a client certificate, opens an
// mTLS dispatch stream, is assigned a job, spawns an engine process, and submits
// what it produced to Ingest on a second connection. The assertion is on rows in
// Postgres, because every layer between the two binaries has to work for a row
// to exist.
func TestEnrollThroughToResults(t *testing.T) {
	h := newHarness(t)
	h.startCore()
	h.startScanPoint()

	eventually(t, "the scan point to enrol", 30*time.Second, func() bool {
		_, err := os.Stat(filepath.Join(h.spData, "cert.pem"))
		return err == nil
	})

	// What is on disk, and what is not. ADR-020 permits exactly one thing to
	// persist on a scan point and this is the check that it is the only one.
	assertDataDir(t, h.spData)

	eventually(t, "observations to reach the database", 60*time.Second, func() bool {
		return h.observationCount() >= taskCount
	})

	subs := h.submissions()
	if len(subs) != 1 {
		t.Fatalf("submissions = %d, want 1", len(subs))
	}
	if subs[0].Status != string(store.SubmitAccepted) {
		t.Errorf("submission status = %q, want accepted", subs[0].Status)
	}
	if subs[0].Incomplete {
		t.Error("a job that ran to completion was submitted as incomplete")
	}

	eventually(t, "the job to be marked completed", 20*time.Second, func() bool {
		status, _ := h.jobStatus()
		return status == string(store.JobCompleted)
	})
	if _, reason := h.jobStatus(); reason == nil || *reason != string(store.TerminationCompleted) {
		t.Errorf("termination_reason = %v, want completed", reason)
	}
}

// assertDataDir enumerates what the runtime wrote.
//
// ADR-020: credential material is memory-only and never written to disk on a
// scan point. The private key is the one carve-out, and it is what makes
// cert_fingerprint a per-device identity rather than a label. An extra file here
// is a finding, not a detail — the whole point of enumerating is that a future
// change adding one has to come past this assertion.
func assertDataDir(t *testing.T, dir string) {
	t.Helper()

	// The complete list. A rotation adds key.pem.prev and cert.pem.prev, kept so
	// a crash between the two renames cannot leave a key matching no
	// certificate; this test enrols and does not rotate, so they are absent
	// here and permitted rather than required.
	want := map[string]os.FileMode{
		"key.pem":       0o600,
		"cert.pem":      0o644,
		"ca.pem":        0o644,
		"identity":      0o644,
		"key.pem.prev":  0o600,
		"cert.pem.prev": 0o644,
	}
	required := map[string]bool{
		"key.pem": true, "cert.pem": true, "ca.pem": true, "identity": true,
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read data dir: %v", err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		mode, expected := want[e.Name()]
		if !expected {
			t.Errorf("unexpected file in the scan point data directory: %s. "+
				"ADR-020 permits the key, the certificate, the chain and the identity "+
				"file, and nothing else — credential material is memory-only.", e.Name())
			continue
		}
		if info.Mode().Perm() != mode {
			t.Errorf("%s has mode %o, want %o", e.Name(), info.Mode().Perm(), mode)
		}
		seen[e.Name()] = true
	}
	for name := range required {
		if !seen[name] {
			t.Errorf("%s was not written", name)
		}
	}

	if info, err := os.Stat(dir); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o700 {
		t.Errorf("the data directory has mode %o, want 0700", info.Mode().Perm())
	}

	// The token is a bearer credential for a fleet identity. It is read once
	// and zeroised; nothing copies it into the data directory.
	for _, e := range entries {
		if b, err := os.ReadFile(filepath.Join(dir, e.Name())); err == nil {
			if containsTokenPrefix(b) {
				t.Errorf("%s contains something shaped like an enrollment token", e.Name())
			}
		}
	}
}

func containsTokenPrefix(b []byte) bool {
	const prefix = "cvap_et_"
	for i := 0; i+len(prefix) <= len(b); i++ {
		if string(b[i:i+len(prefix)]) == prefix {
			return true
		}
	}
	return false
}

// TestSelfAbortOnLeaseLoss is ADR-012, proved by severing the lease mid-job.
//
// The requirement is not that a log line appears. It is that the runtime STOPS
// WORK, zeroises credentials and submits what it gathered marked incomplete —
// which is the record ADR-012's operator escalation is about, and the only
// account of what an intrusive job touched before it died.
//
// Severed the way a reassignment does it: the lease is released and a new epoch
// granted to the same scan point out of band, so the runtime's next renewal is
// answered LEASE_STATE_LOST. That is the real mechanism, not a simulated one.
func TestSelfAbortOnLeaseLoss(t *testing.T) {
	h := newSlowHarness(t)
	h.startCore()
	h.startScanPoint()

	// Wait until the job is actually running under a lease.
	var epoch int64
	eventually(t, "the job to be leased", 40*time.Second, func() bool {
		e, err := h.currentLease()
		if err != nil {
			return false
		}
		epoch = e
		return true
	})
	// A beat, so the engine is genuinely mid-job rather than just spawned.
	// Nothing observable in Postgres marks that point — the runtime submits
	// once, at the terminal — so the lease's existence plus a short wait is the
	// signal, and the assertions below prove the job really was cut short.
	time.Sleep(1500 * time.Millisecond)
	if h.observationCount() >= taskCount {
		t.Skip("the job finished before the lease could be severed; raise slowPerTarget")
	}

	// Sever it. ReleaseAny then Grant is exactly what a reassignment does, and
	// it makes the scan point's next renewal fail its epoch check.
	if err := h.db.Write(context.Background(), h.tenant, func(ctx context.Context, c *store.Conn) error {
		if err := (store.Leases{}).ReleaseAny(ctx, c, h.jobID, epoch, store.LeaseLost); err != nil {
			return err
		}
		_, err := (store.Leases{}).Grant(ctx, c, h.jobID, h.enrolledScanPoint(), store.LeaseTTL)
		return err
	}); err != nil {
		t.Fatalf("sever lease: %v", err)
	}
	t.Logf("severed the lease at epoch %d", epoch)

	// The results arrive, marked incomplete, with lease_lost as the reason.
	eventually(t, "an incomplete submission", 60*time.Second, func() bool {
		for _, s := range h.submissions() {
			if s.Incomplete {
				return true
			}
		}
		return false
	})

	var found submissionRow
	for _, s := range h.submissions() {
		if s.Incomplete {
			found = s
		}
	}
	if found.Reason == nil || *found.Reason != string(store.TerminationLeaseLost) {
		t.Errorf("termination_reason = %v, want lease_lost", found.Reason)
	}
	// Stored, not dropped. Whether it reaches the finding pipeline is Core's
	// decision; that it was kept is ADR-026's, and it is not negotiable.
	if found.Status != string(store.SubmitAccepted) &&
		found.Status != string(store.SubmitAcceptedQuarantined) {
		t.Errorf("submission status = %q; results from a job that lost its lease are "+
			"always stored (ADR-026)", found.Status)
	}

	// And the work actually STOPPED. Observations must stop arriving, which is
	// the difference between a self-abort and a log line about one.
	settled := h.observationCount()
	time.Sleep(3 * time.Second)
	if after := h.observationCount(); after != settled {
		t.Errorf("observations went from %d to %d after the abort settled; "+
			"the engine is still running", settled, after)
	}
	if settled >= taskCount {
		t.Errorf("the job produced all %d observations despite losing its lease; "+
			"it did not stop", taskCount)
	}
	if settled == 0 {
		t.Error("no observations were submitted at all; a job that lost its lease " +
			"must still submit what it gathered (ADR-026)")
	}
	t.Logf("stopped at %d of %d observations", settled, taskCount)
}

// TestEngineCrashIsEngineFailure covers the outcome that is neither lease loss,
// cancellation nor completion.
//
// The engine subprocess is killed from outside. The runtime must notice, submit
// what was buffered marked incomplete with ENGINE_FAILURE, and NOT restart the
// engine — a crashed engine restarted under the same lease is duplicate
// execution against the same targets, and whether the work re-runs is Core's
// decision through reassign_safe, not the runtime's.
func TestEngineCrashIsEngineFailure(t *testing.T) {
	h := newSlowHarness(t)
	h.startCore()
	h.startScanPoint()

	pid := findEngine(t, h)
	// Mid-job, for the same reason as the lease test: the engine has to have
	// produced something for "results are still submitted" to mean anything.
	time.Sleep(1500 * time.Millisecond)
	if h.observationCount() >= taskCount {
		t.Skip("the job finished before the engine could be killed; raise slowPerTarget")
	}
	t.Logf("killing engine pid %d", pid)
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatalf("kill engine: %v", err)
	}

	eventually(t, "the job to be reported failed", 60*time.Second, func() bool {
		_, reason := h.jobStatus()
		return reason != nil && *reason == string(store.TerminationEngineFailure)
	})

	subs := h.submissions()
	if len(subs) == 0 {
		t.Fatal("no submission after the engine died; results are never discarded (ADR-026)")
	}
	last := subs[len(subs)-1]
	if !last.Incomplete {
		t.Error("a job whose engine died was not marked incomplete")
	}
	if last.Reason == nil || *last.Reason != string(store.TerminationEngineFailure) {
		t.Errorf("termination_reason = %v, want engine_failure. It is not lease loss, "+
			"not cancellation and not completion, and folding it into any of those "+
			"sends an operator to look in the wrong place.", last.Reason)
	}

	// No restart. A second engine would produce more observations under the
	// same lease.
	settled := h.observationCount()
	time.Sleep(3 * time.Second)
	if after := h.observationCount(); after != settled {
		t.Errorf("observations went from %d to %d after the engine died; the runtime "+
			"restarted it, which is duplicate execution against the same targets "+
			"under a lease that says one execution", settled, after)
	}
}

// findEngine locates the engine subprocess by walking /proc for a child of the
// scan point.
func findEngine(t *testing.T, h *harness) int {
	t.Helper()
	var pid int
	eventually(t, "the engine subprocess to appear", 40*time.Second, func() bool {
		entries, err := os.ReadDir("/proc")
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			raw, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
			if err != nil {
				continue
			}
			// "pid (comm) state ppid ..." — comm may contain spaces, so read
			// backwards from the closing parenthesis.
			s := string(raw)
			close := lastIndexByte(s, ')')
			if close < 0 {
				continue
			}
			var state string
			var ppid int
			if _, err := sscan(s[close+1:], &state, &ppid); err != nil {
				continue
			}
			if ppid != h.spCmd.Process.Pid {
				continue
			}
			p := atoi(e.Name())
			if p > 0 {
				pid = p
				return true
			}
		}
		return false
	})
	return pid
}
