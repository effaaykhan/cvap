package scanpoint

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
	"github.com/effaaykhan/cvap/internal/enginewire"
)

// ============================================================================
// Shutdown must not exit before a self-aborted job's results are enqueued.
// ============================================================================
//
// On SIGTERM the runtime self-aborts each in-flight job (stop the engine,
// zeroise, submit what it gathered marked incomplete — ADR-026). shutdown()
// waited on j.done, which closes the instant runJob returns — i.e. when the
// engine is reaped — while the abort goroutine is still in terminate(), before
// its submit.Enqueue. So shutdown returned, main saw an empty buffer, logged a
// false "drained" and exited, and the gathered results were lost on every
// SIGTERM (rolling restart, deploy, node drain). The fix waits on j.terminated,
// which closes only after terminate() has enqueued.
//
// This drives the REAL shutdown path — r.shutdown → r.abort → r.terminate, and
// the real runJob closing j.done — with fakes only at the edges (the engine host
// and the submitter). The determinism is not left to scheduling: the fake host's
// results() blocks until the test releases it, which sits INSIDE terminate()
// before the Enqueue. So under the bug, shutdown returns on j.done while Enqueue
// is unreachable (nothing is buffered, deterministically); under the fix,
// shutdown cannot return until the test releases results() and terminate()
// enqueues. The mutation swaps the seam back to j.done and this fails every run.
//
// The engine host seam is in-process and reachable, so it carries a real overlay
// sabotage (ADR-056's observation-only exemption is for logic sealed in a
// separately-built binary; the e2e test covers that boundary separately).
//
// mutate:subject internal/scanpoint/runtime.go
// mutate:test    ./internal/scanpoint/ -run TestShutdownWaitsForResultsBeforeExiting
//
// mutate:case    shutdown waits on the engine-reaped signal, not the results-enqueued one
// mutate:old     		case <-j.terminated:
// mutate:new     		case <-j.done:
func TestShutdownWaitsForResultsBeforeExiting(t *testing.T) {
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))
	submit := NewSubmitter(discard, nil) // never Run; we only read Buffered()
	r := &Runtime{
		log:    discard,
		submit: submit,
		now:    time.Now,
		jobs:   make(map[string]*job),
		out:    make(chan *scanpointv1.ScanPointMessage, 64),
	}

	fh := newBlockingHost()
	ctx, cancel := context.WithCancel(context.Background())
	j := &job{
		id:         "job-1",
		host:       fh,
		cancel:     cancel,
		done:       make(chan struct{}),
		terminated: make(chan struct{}),
	}
	r.mu.Lock()
	r.jobs[j.id] = j
	r.mu.Unlock()

	go r.runJob(ctx, j)
	<-fh.started // the engine is "running" and runJob is blocked in wait()

	returned := make(chan struct{})
	go func() { r.shutdown(); close(returned) }()

	// The bug returns on j.done before terminate() can enqueue (results() is
	// blocked); the fix stays blocked on j.terminated until we release it.
	select {
	case <-returned:
		if n, _ := submit.Buffered(); n == 0 {
			close(fh.release) // let the abort goroutine finish before we fail
			t.Fatal("shutdown returned before the self-aborted job's results were enqueued; " +
				"a SIGTERM here exits with them still ungathered and loses them (ADR-026)")
		}
	case <-time.After(2 * time.Second):
		// Correct: shutdown is blocked waiting for terminate() to enqueue.
	}

	close(fh.release) // release results(); terminate() now enqueues and closes terminated
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown did not return after results were released")
	}

	if n, _ := submit.Buffered(); n == 0 {
		t.Fatal("the self-aborted job's results were never enqueued")
	}
}

// blockingHost is an engineHostRunner whose results() blocks until released, so
// the test controls exactly when terminate() reaches its Enqueue.
type blockingHost struct {
	started  chan struct{}
	stopped  chan struct{}
	release  chan struct{}
	stopOnce sync.Once
}

func newBlockingHost() *blockingHost {
	return &blockingHost{
		started: make(chan struct{}),
		stopped: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (h *blockingHost) start(context.Context, []enginewire.Target, engineBudget) error {
	close(h.started)
	return nil
}
func (h *blockingHost) authoriseAll([]enginewire.Target) error { return nil }
func (h *blockingHost) pump()                                  {}
func (h *blockingHost) wait() EngineOutcome {
	<-h.stopped
	return EngineStopped
}
func (h *blockingHost) stop(time.Duration) {
	h.stopOnce.Do(func() { close(h.stopped) })
}
func (h *blockingHost) results() ([]enginewire.Observation, uint32, bool) {
	<-h.release
	obs := []enginewire.Observation{{
		ObservationID: uuid.NewString(),
		TaskID:        uuid.NewString(),
		Type:          "host",
		Payload:       []byte(`{"probed":false}`),
		ObservedAt:    time.Now(),
	}}
	return obs, 1, false
}
