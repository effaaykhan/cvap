package scanpoint

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh/agent"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
	"github.com/effaaykhan/cvap/internal/enginewire"
	"github.com/effaaykhan/cvap/internal/hostkeytrust"
)

// ============================================================================
// Severing a credentialed job: stop, THEN zeroise, THEN submit — measured by
// probing the signing socket at each stage, not by reading the code path.
// ============================================================================
//
// ADR-020 wants the key gone on lease loss and abort; ADR-026 wants the results
// submitted regardless; ADR-057 fixes the order between them. Session 9's F9
// finding was exactly this shape with both ADRs honoured at the store and the
// process gone before the goroutine ran, so the assertion here is about what an
// engine can DO at each instant, from its own end of the agent socket:
//
//   - when stop() is requested, signing still works — the engine gets its grace
//     to finish the observation in hand before the key dies;
//   - when results() is gathered (inside terminate, before Enqueue), signing
//     has ALREADY failed — the key died before anything that can block;
//   - after terminate, the results are buffered and the JobTerminal attests
//     credentials_zeroised, answered over the agent's copy as well as the
//     Credential's.
//
// Two severs, because they enter through different doors: a LeaseGrant LOST
// (Core said so) and shutdown (the process is leaving — the F9 door).
//
// The mutation the harness carries is the F9 one: zeroise reaches the
// Credential and skips the agent, so the key the engine actually signs with
// survives and the attestation is answered one layer above it. The ORDERING
// mutation (abort zeroising after terminate's Enqueue, at both sites) is
// two-line and was run by hand when this test was written — it fails at
// "signing still worked when results() were gathered" in both severs.
//
// mutate:subject internal/scanpoint/job.go
// mutate:test    ./internal/scanpoint/ -run TestSeveredCredentialedJobStopsThenZeroisesThenSubmits|TestAttestationCoversTheAgentCopy
//
// mutate:case    zeroise skips the agent's copy of the key
// mutate:old     	for _, agent := range agents {
// mutate:new     	for _, agent := range agents[:0] {
func TestSeveredCredentialedJobStopsThenZeroisesThenSubmits(t *testing.T) {
	for _, tc := range []struct {
		name   string
		sever  func(r *Runtime, j *job)
		reason scanpointv1.TerminationReason
	}{
		{"lease lost", func(r *Runtime, j *job) {
			r.onLeaseGrant(&scanpointv1.LeaseGrant{JobId: j.id, LeaseEpoch: j.currentEpoch(),
				State: scanpointv1.LeaseState_LEASE_STATE_LOST})
		}, scanpointv1.TerminationReason_LEASE_LOST},
		{"shutdown", func(r *Runtime, j *job) { r.shutdown() }, scanpointv1.TerminationReason_LEASE_LOST},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, submit := testRuntime()
			fh := newSigningHost(submit)
			j := credentialedJob(t, fh)
			r.mu.Lock()
			r.jobs[j.id] = j
			r.mu.Unlock()

			ctx, cancel := context.WithCancel(context.Background())
			j.cancel = cancel
			go r.runJob(ctx, j)

			cred, _ := ed25519CredentialPEM(t)
			r.onCredential(&scanpointv1.CredentialGrant{
				GrantId: cred.GrantID, JobId: j.id, Material: cred.Reveal(), Scope: []string{"192.0.2.7"},
				ExpiresUnix: time.Now().Add(time.Hour).Unix(), CredKind: scanpointv1.CredKind_RAW_SECRET,
			})
			select {
			case <-fh.started:
			case <-time.After(5 * time.Second):
				t.Fatal("the engine never started after its grant arrived")
			}
			if err := fh.trySign(); err != nil {
				t.Fatalf("signing over the agent socket failed while the job was running: %v", err)
			}

			tc.sever(r, j)
			select {
			case <-j.terminated:
			case <-time.After(10 * time.Second):
				t.Fatal("the severed job never reached terminate()")
			}

			if fh.signAtStop != nil {
				t.Errorf("signing had already failed when stop() was requested: %v — the key "+
					"was zeroised BEFORE the engine was stopped, so the grace window ADR-027 "+
					"gives an engine to finish its observation ran without a credential", fh.signAtStop)
			}
			if fh.signAtResults == nil {
				t.Error("signing still worked when results() were gathered for submission — the key " +
					"outlived the stop and was alive going into the upload, which is the exposure " +
					"ADR-057 refuses (credential lifetime tied to how long a drain takes)")
			}
			if fh.bufferedAtResults != 0 {
				t.Errorf("%d submission(s) were already buffered when results() ran; submit must come last",
					fh.bufferedAtResults)
			}
			if n, _ := submit.Buffered(); n != 1 {
				t.Errorf("buffered submissions after terminate = %d, want 1 (ADR-026: never discarded)", n)
			}
			if !j.credentialsZeroised() {
				t.Error("credentialsZeroised() is false after terminate")
			}
			term := drainTerminal(t, r, j.id)
			if !term.GetCredentialsZeroised() {
				t.Error("JobTerminal.credentials_zeroised is false after a severed credentialed job")
			}
			if term.GetReason() != tc.reason {
				t.Errorf("terminal reason = %v, want %v", term.GetReason(), tc.reason)
			}
		})
	}
}

// The runtime's half of the resolve-then-abort window: a grant that lands once
// the job is already terminal is zeroised on arrival, not appended to a list the
// terminal path has already walked.
func TestGrantArrivingAfterAbortIsZeroisedOnArrival(t *testing.T) {
	j := &job{id: "j", credReady: make(chan struct{})}
	if !j.beginAbort(scanpointv1.TerminationReason_CANCELLED) {
		t.Fatal("beginAbort")
	}
	cred, _ := ed25519CredentialPEM(t)
	j.addCredential(cred)
	if !cred.Zeroised() {
		t.Fatal("a grant that arrived after the job began aborting was retained un-zeroised")
	}
	if got := j.firstCredential(); got != nil {
		t.Fatal("the late grant was appended to the job; it would outlive the terminal path")
	}
	if !j.credentialsZeroised() {
		t.Fatal("credentialsZeroised() false after a late grant")
	}
}

// The attestation must answer over the AGENT's copy of the key, not only the
// Credential's. Zeroising the Credential alone leaves the keyring signing.
func TestAttestationCoversTheAgentCopy(t *testing.T) {
	cred, _ := ed25519CredentialPEM(t)
	a, err := NewCredAgent(cred)
	if err != nil {
		t.Fatal(err)
	}
	j := &job{id: "j"}
	j.creds = append(j.creds, cred)
	j.addAgent(a)
	cred.Zeroise()
	if j.credentialsZeroised() {
		t.Fatal("credentialsZeroised() answered true with the agent's key still live — " +
			"the attestation was one layer above where the key lives (F9 shape)")
	}
	j.zeroiseCredentials()
	if !j.credentialsZeroised() || !a.Zeroised() {
		t.Fatal("zeroiseCredentials did not reach the agent")
	}
}

// A host job is validated before it exists: no user, no header, no material
// (TOFU), unknown source — each is refused with the reason in detail and no job
// enters the table, so nothing can be spawned for it.
func TestHostJobWithoutAcceptableTrustMaterialIsRefusedBeforeAnyProcess(t *testing.T) {
	good, err := hostkeytrust.Compose(hostkeytrust.SourceObserved, "192.0.2.7 SHA256:abc")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, user, knownHosts, want string
	}{
		{"no cred_user", "", good, "no cred_user"},
		{"no header", "lab", "192.0.2.7 SHA256:abc\n", "no trust-source header"},
		{"header but no material (TOFU)", "lab", hostkeytrust.HeaderPrefix + "observed\n", "trust-on-first-use is not permitted"},
		{"unknown source", "lab", hostkeytrust.HeaderPrefix + "tofu\n192.0.2.7 SHA256:abc\n", "unknown trust source"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := testRuntime()
			r.engines = &EngineSet{byKind: map[string]string{EngineKindHost: "/nonexistent/engine"}}
			r.onAssignment(context.Background(), &scanpointv1.JobAssignment{
				JobId: "job-h", Engine: EngineKindHost, LeaseEpoch: 1,
				LeaseExpiresUnix: time.Now().Add(time.Minute).Unix(),
				Constraints:      &scanpointv1.ScanConstraints{AllowedTargets: []string{"192.0.2.0/24"}},
				Tasks:            []*scanpointv1.Task{{TaskId: "t", Target: "192.0.2.7"}},
				CredUser:         tc.user, KnownHosts: tc.knownHosts,
			})
			if r.lookup("job-h") != nil {
				t.Fatal("a refused host job entered the job table")
			}
			term := drainTerminal(t, r, "job-h")
			if term.GetReason() != scanpointv1.TerminationReason_ENGINE_FAILURE {
				t.Errorf("reason = %v, want ENGINE_FAILURE", term.GetReason())
			}
			if !strings.Contains(term.GetDetail(), tc.want) {
				t.Errorf("detail %q does not name the refusal %q", term.GetDetail(), tc.want)
			}
			if !term.GetCredentialsZeroised() {
				t.Error("a job that held nothing must still attest zeroised")
			}
		})
	}
}

// A credentialed job whose grant never arrives fails without spawning, and does
// not sit renewing a lease for work it cannot start.
func TestCredentialedJobFailsWhenNoGrantArrives(t *testing.T) {
	old := CredentialGrantWait
	CredentialGrantWait = 100 * time.Millisecond
	t.Cleanup(func() { CredentialGrantWait = old })

	r, _ := testRuntime()
	fh := newSigningHost(nil)
	j := credentialedJob(t, fh)
	r.mu.Lock()
	r.jobs[j.id] = j
	r.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	j.cancel = cancel
	go r.runJob(ctx, j)
	select {
	case <-j.terminated:
	case <-time.After(5 * time.Second):
		t.Fatal("the job did not fail after the grant wait elapsed")
	}
	select {
	case <-fh.started:
		t.Fatal("the engine was started with no credential")
	default:
	}
	term := drainTerminal(t, r, j.id)
	if term.GetReason() != scanpointv1.TerminationReason_ENGINE_FAILURE ||
		!strings.Contains(term.GetDetail(), "no credential grant") {
		t.Errorf("terminal = %v %q, want ENGINE_FAILURE naming the missing grant", term.GetReason(), term.GetDetail())
	}
}

// ============================================================================
// The agent socket reaches a REAL child on fd 3, and the child can sign with it
// while holding no key. A helper process, not a fake host, because the ExtraFiles
// plumbing is exactly the kind of thing a fake would assert into existence.
// ============================================================================
func TestEngineReceivesTheAgentSocketOnFD3AndCanSign(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a helper process")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// engineEnv() hands the child PATH/HOME/TZ/LANG only, so the helper trigger
	// cannot be an inherited variable; the wrapper script sets it itself.
	script := t.TempDir() + "/engine.sh"
	if err := os.WriteFile(script, []byte("#!/bin/sh\nCVAP_TEST_HELPER_ENGINE=1 exec "+exe+
		" -test.run='^TestHelperEngineProcess$'\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	r, submit := testRuntime()
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))
	known, _ := hostkeytrust.Compose(hostkeytrust.SourceOperator, "192.0.2.7 ssh-ed25519 AAAA test")
	j := &job{
		id: "job-fd", epoch: 1,
		constraints: &scanpointv1.ScanConstraints{AllowedTargets: []string{"192.0.2.0/24"}},
		tasks:       []*scanpointv1.Task{{TaskId: "t1", Target: "192.0.2.7"}},
		host:        newEngineHost(discard, script, "job-fd", []string{"192.0.2.0/24"}, nil),
		done:        make(chan struct{}), terminated: make(chan struct{}),
		needsCred: true, credUser: "lab", knownHosts: known, trust: hostkeytrust.SourceOperator,
		credReady: make(chan struct{}),
	}
	r.mu.Lock()
	r.jobs[j.id] = j
	r.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	j.cancel = cancel
	go r.runJob(ctx, j)

	cred, _ := ed25519CredentialPEM(t)
	r.onCredential(&scanpointv1.CredentialGrant{
		GrantId: "g", JobId: j.id, Material: cred.Reveal(), Scope: []string{"192.0.2.7"},
		ExpiresUnix: time.Now().Add(time.Hour).Unix(), CredKind: scanpointv1.CredKind_RAW_SECRET,
	})
	select {
	case <-j.terminated:
	case <-time.After(20 * time.Second):
		t.Fatal("the helper engine never finished")
	}
	term := drainTerminal(t, r, j.id)
	if term.GetReason() != scanpointv1.TerminationReason_COMPLETED {
		t.Fatalf("terminal = %v %q, want COMPLETED", term.GetReason(), term.GetDetail())
	}
	if !term.GetCredentialsZeroised() || !j.credentialsZeroised() {
		t.Error("the agent's key survived a completed job")
	}
	obs, _, _ := j.host.results()
	if len(obs) != 1 {
		t.Fatalf("observations = %d, want 1", len(obs))
	}
	got := string(obs[0].Payload)
	for _, want := range []string{`"signed":true`, `"cred_user":"lab"`, `"trust_source":"operator"`} {
		if !strings.Contains(got, want) {
			t.Errorf("helper payload %s lacks %s", got, want)
		}
	}
	if n, _ := submit.Buffered(); n != 1 {
		t.Errorf("buffered = %d, want 1", n)
	}
}

// TestHelperEngineProcess is the child of the test above. It behaves as an
// engine: reads the job on stdin, opens fd 3 as an agent client, signs a
// challenge with the ONLY key the agent offers (holding none itself), verifies
// the signature against the agent's public key, and reports what it was handed.
func TestHelperEngineProcess(t *testing.T) {
	if os.Getenv("CVAP_TEST_HELPER_ENGINE") != "1" {
		t.Skip("helper process entry point")
	}
	fail := func(msg string) {
		_, _ = os.Stderr.WriteString("helper: " + msg + "\n")
		os.Exit(2)
	}
	in := enginewire.NewReader(os.Stdin)
	out := enginewire.NewWriter(os.Stdout)
	msg, err := in.ReadTo()
	if err != nil || msg.Kind != enginewire.KindJob {
		fail("no job on stdin")
	}
	f := os.NewFile(3, "agent")
	conn, err := net.FileConn(f)
	if err != nil {
		fail("fd 3 is not a socket: " + err.Error())
	}
	client := agent.NewClient(conn)
	signers, err := client.Signers()
	if err != nil || len(signers) != 1 {
		fail("agent offered no signer")
	}
	challenge := []byte("challenge")
	sig, err := signers[0].Sign(rand.Reader, challenge)
	if err != nil {
		fail("sign: " + err.Error())
	}
	if err := signers[0].PublicKey().Verify(challenge, sig); err != nil {
		fail("signature did not verify: " + err.Error())
	}
	src, _, err := hostkeytrust.Parse(msg.KnownHosts)
	if err != nil {
		fail("known_hosts: " + err.Error())
	}
	_ = out.WriteFrom(enginewire.FromEngine{Kind: enginewire.KindObservation, Observation: &enginewire.Observation{
		ObservationID: uuid.NewString(), TaskID: msg.Targets[0].TaskID, Type: "host",
		Payload:    []byte(`{"signed":true,"cred_user":"` + msg.CredUser + `","trust_source":"` + string(src) + `"}`),
		ObservedAt: time.Now().UTC(),
	}})
	_ = out.WriteFrom(enginewire.FromEngine{Kind: enginewire.KindDone})
	os.Exit(0) // never let the test runner print PASS onto the engine wire
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func testRuntime() (*Runtime, *Submitter) {
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))
	submit := NewSubmitter(discard, nil)
	return &Runtime{
		log: discard, submit: submit, now: time.Now,
		jobs: make(map[string]*job),
		out:  make(chan *scanpointv1.ScanPointMessage, 64),
	}, submit
}

func credentialedJob(t *testing.T, host engineHostRunner) *job {
	t.Helper()
	known, err := hostkeytrust.Compose(hostkeytrust.SourceObserved, "192.0.2.7 SHA256:abc")
	if err != nil {
		t.Fatal(err)
	}
	j := &job{
		id: "job-cred", epoch: 1,
		constraints: &scanpointv1.ScanConstraints{AllowedTargets: []string{"192.0.2.0/24"}},
		tasks:       []*scanpointv1.Task{{TaskId: "t1", Target: "192.0.2.7"}},
		host:        host,
		done:        make(chan struct{}), terminated: make(chan struct{}),
		needsCred: true, credUser: "lab", knownHosts: known, trust: hostkeytrust.SourceObserved,
		credReady: make(chan struct{}),
	}
	j.setExpiry(time.Now().Add(time.Minute))
	return j
}

func drainTerminal(t *testing.T, r *Runtime, jobID string) *scanpointv1.JobTerminal {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case m := <-r.out:
			if term := m.GetTerminal(); term != nil && term.GetJobId() == jobID {
				return term
			}
		case <-deadline:
			t.Fatalf("no JobTerminal for %s", jobID)
		}
	}
}

// signingHost is an engineHostRunner standing in for the credhost engine: it
// takes the agent socket the runtime hands it at start, and probes whether that
// socket still signs at the two instants the ordering test cares about.
type signingHost struct {
	submit *Submitter

	started  chan struct{}
	stopped  chan struct{}
	stopOnce sync.Once

	// gathered closes when results() has run. wait() returns only after it, so
	// the fake models an engine that is slow to be reaped — SIGTERM sent, grace
	// running — while the abort goroutine has already moved on to terminate.
	// That is the window in which the abort path's OWN zeroise is the only one
	// that can precede the submission; runJob's deferred zeroise (the belt to
	// this brace) has not fired yet because the engine is not reaped.
	gathered     chan struct{}
	gatheredOnce sync.Once

	mu     sync.Mutex
	client agent.ExtendedAgent

	signAtStop        error
	signAtResults     error
	bufferedAtResults int
}

func newSigningHost(submit *Submitter) *signingHost {
	return &signingHost{submit: submit, started: make(chan struct{}), stopped: make(chan struct{}),
		gathered: make(chan struct{})}
}

func (h *signingHost) start(_ context.Context, _ []enginewire.Target, b engineBudget) error {
	if b.Cred == nil || b.Cred.Agent == nil {
		return errors.New("signingHost: no agent socket in the budget")
	}
	conn, err := net.FileConn(b.Cred.Agent)
	if err != nil {
		return err
	}
	h.mu.Lock()
	h.client = agent.NewClient(conn)
	h.mu.Unlock()
	close(h.started)
	return nil
}

// trySign is the probe: a signature request over the socket, as the engine
// would make it. Fails once the runtime end is closed by Zeroise.
func (h *signingHost) trySign() error {
	h.mu.Lock()
	c := h.client
	h.mu.Unlock()
	if c == nil {
		return errors.New("no agent client")
	}
	signers, err := c.Signers()
	if err != nil {
		return err
	}
	if len(signers) == 0 {
		return errors.New("no signers")
	}
	_, err = signers[0].Sign(rand.Reader, []byte("probe"))
	return err
}

func (h *signingHost) authoriseAll([]enginewire.Target) error { return nil }
func (h *signingHost) pump()                                  {}
func (h *signingHost) wait() EngineOutcome {
	<-h.stopped
	<-h.gathered
	return EngineStopped
}
func (h *signingHost) stop(time.Duration) {
	h.stopOnce.Do(func() {
		h.signAtStop = h.trySign()
		close(h.stopped)
	})
}
func (h *signingHost) results() ([]enginewire.Observation, uint32, bool) {
	h.signAtResults = h.trySign()
	if h.submit != nil {
		h.bufferedAtResults, _ = h.submit.Buffered()
	}
	h.gatheredOnce.Do(func() { close(h.gathered) })
	return []enginewire.Observation{{
		ObservationID: uuid.NewString(), TaskID: "t1", Type: "package",
		Payload: []byte(`{"address":"192.0.2.7"}`), ObservedAt: time.Now(),
	}}, 1, false
}

// A zeroise landing before the agent's serving goroutine is scheduled used to
// hand ServeAgent a nil conn and panic the whole scan point — reproduced through
// the scope-refusal path 2 of 3 runs by the scan-safety audit. A goroutine panic
// cannot be recovered by a test, so this loop is the probe: it either survives
// or the binary dies.
func TestAgentZeroiseRacingItsOwnServeGoroutineDoesNotPanic(t *testing.T) {
	for i := 0; i < 200; i++ {
		cred, _ := ed25519CredentialPEM(t)
		a, err := NewCredAgent(cred)
		if err != nil {
			t.Fatal(err)
		}
		f, err := a.EngineFile()
		if err != nil {
			t.Fatal(err)
		}
		a.Zeroise()
		_ = f.Close()
	}
}

// The engine end of the agent socket is close-on-exec, so a sibling engine
// spawned for another job while this one's file is open does not inherit a
// signing oracle (security review: 16 of 20 concurrent spawns did).
func TestAgentSocketIsCloseOnExec(t *testing.T) {
	cred, _ := ed25519CredentialPEM(t)
	a, err := NewCredAgent(cred)
	if err != nil {
		t.Fatal(err)
	}
	f, err := a.EngineFile()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	defer a.Zeroise()
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_GETFD, 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	if flags&syscall.FD_CLOEXEC == 0 {
		t.Fatal("the engine end of the agent socket is inheritable by every child this process forks")
	}
}
