package scanpoint

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/effaaykhan/cvap/internal/enginewire"
	"github.com/effaaykhan/cvap/internal/scope"
	"github.com/effaaykhan/cvap/internal/target"
)

// EngineOutcome is how an engine process ended.
type EngineOutcome int

const (
	// EngineCompleted: the engine reported done and exited 0.
	EngineCompleted EngineOutcome = iota

	// EngineStopped: the runtime asked it to stop and it did. The reason
	// belongs to whoever asked — a cancellation, a kill, a lost lease — not to
	// the engine.
	EngineStopped

	// EngineFailed: it died on its own. A segfault, an OOM kill, a non-zero
	// exit, or stdout closing without a done message.
	//
	// This is a THIRD outcome on purpose. It is not lease loss, not
	// cancellation and not completion, and folding it into any of those
	// misattributes the failure: an operator reading `lease_lost` goes looking
	// at the network, and one reading `completed` does not go looking at all.
	// TerminationReason.ENGINE_FAILURE has existed since the contract was
	// frozen; nothing produced it until there was a process that could fail.
	EngineFailed
)

func (o EngineOutcome) String() string {
	switch o {
	case EngineCompleted:
		return "completed"
	case EngineStopped:
		return "stopped"
	default:
		return "failed"
	}
}

// engineHost runs one engine process for one job.
//
// ============================================================================
// The runtime authorises. The engine asks.
// ============================================================================
//
// ADR-027 puts scope enforcement at exactly two sites, Core and this runtime,
// and never in an engine. Two things follow, and both are here rather than in
// the engine:
//
//   - Targets are checked against the job's ScanConstraints BEFORE they are
//     written to the engine's stdin. Core checked them too; this is the second
//     site, and it exists because Core may have a planning bug and because a
//     scan point runs a build Core does not control.
//   - A target an engine discovers mid-scan comes back as an authorise request
//     and is answered here. The engine holds no allowlist and no exclusions, so
//     it cannot reach a verdict even if it wanted to.
//
// Both use internal/scope, the same matcher Core uses, so the two sites cannot
// disagree about a rule — only about whether to ask, which is what the
// conformance suites assert.
type engineHost struct {
	log *slog.Logger

	binary string
	jobID  string

	// allowed and exclusions are this job's authorised scope, from
	// ScanConstraints. Held here because this is the only component that
	// decides; nothing downstream of it gets a vote.
	allowed    []string
	exclusions []string

	cmd  *exec.Cmd
	in   io.WriteCloser
	out  *enginewire.Reader
	wire *enginewire.Writer

	mu sync.Mutex
	// stopRequested distinguishes "we killed it" from "it died". Without it a
	// SIGKILL we sent looks exactly like a crash, and every cancellation would
	// be reported as ENGINE_FAILURE.
	stopRequested bool

	// hasReaped is set by wait() before it closes reaped, so a stop that raced
	// the grace timer can check it without a second wait.
	hasReaped bool

	observations  []enginewire.Observation
	observedBytes int
	truncated     bool
	sent          uint32
	sawDone       bool

	// reaped is closed by wait(), the ONLY caller of cmd.Wait().
	//
	// stop() used to run its own Process.Wait in a goroutine, so two reapers
	// raced for one child: one won and the other got "no child processes", and
	// a stop arriving after the engine had already been reaped signalled a pid
	// the kernel had released. The runtime spawns every engine with Setpgid, so
	// its own next engine becomes a process-group leader — under a container
	// pid_max that recycle is reachable, and the effect is job A's stale stop
	// killing job B's engine group.
	reaped chan struct{}
}

// MaxJobObservations and MaxJobObservationBytes bound what one engine may
// accumulate before submission.
//
// enginewire.MaxLine bounds ONE message; the result buffer's own ceiling is only
// consulted after the job ends. Between the two, an engine emitting large
// observations in a loop grows the runtime's heap without limit — measured at
// 187 MiB against execution-plan §5's 512 MB RSS ceiling, in the process that
// holds every other job's credentials. An engine is by design a parser of
// hostile input, so a target that drives one into a loop is a denial of service
// against the fleet requiring no compromise at all.
//
// Exceeding either bound truncates and sets incomplete on the submission. NOT a
// silent drop: reporting a truncated scan as a whole one is under-scanning that
// looks like a clean run, which is the worst failure this system has.
const (
	MaxJobObservations     = 50_000
	MaxJobObservationBytes = 32 << 20
)

// ErrOutOfScope means a target Core assigned failed this runtime's own check.
//
// Fail closed and fail LOUD: the job is refused rather than trimmed. A runtime
// that quietly dropped the offending target would scan the rest and report
// success, which turns a disagreement between the two enforcement sites into a
// silent partial scan — and the disagreement is the single most important thing
// an operator could be told, because it means Core planned work this scan point
// was not willing to do.
var ErrOutOfScope = errors.New("scanpoint: a target is outside the job's authorised scope")

// errStopBeforeStart means a stop was requested before the engine was spawned.
//
// The window is small and it is the one that matters: receiveLoop delivers
// messages back to back, so a CancelJob or a KillSwitch immediately following an
// assignment reaches the terminal path microseconds before the job's goroutine
// reaches the spawn. Without this check the runtime reported the job stopped,
// acknowledged the cancellation to Core, and then started the work — an engine
// running outside the job table, unreachable by a second cancel, by the kill
// switch or by the lease watchdog. Two independent reviews reproduced it.
var errStopBeforeStart = errors.New("scanpoint: the job was stopped before its engine started")

func newEngineHost(log *slog.Logger, binary, jobID string, allowed, exclusions []string) *engineHost {
	return &engineHost{
		log:        log,
		binary:     binary,
		jobID:      jobID,
		allowed:    allowed,
		exclusions: exclusions,
		reaped:     make(chan struct{}),
	}
}

// engineEnv is the ENTIRE environment an engine process receives.
//
// Explicit, because inheriting os.Environ() handed the engine
// CVAP_SP_ENROLLMENT_TOKEN_FILE and CVAP_SP_DATA_DIR — the paths to the
// enrollment token and to key.pem — which it can read, running as the same uid.
// config.go argues at length that the token lives in a file rather than an
// environment variable so that "every child, including engine processes, which
// must never see it" does not inherit it, and then the engine inherited the path
// to it anyway.
//
// It is also unbounded going forward: any secret an operator puts in the scan
// point's environment, or that a co-located deployment leaks in, would reach
// /proc/<engine-pid>/environ. Engines that need configuration get it in the
// KindJob message, where the contract can see it.
func engineEnv() []string {
	out := make([]string, 0, 4)
	for _, k := range []string{"PATH", "HOME", "TZ", "LANG"} {
		if v, ok := os.LookupEnv(k); ok {
			out = append(out, k+"="+v)
		}
	}
	return out
}

// authorise is the runtime-side scope check, and the only place a verdict is
// reached.
//
// ============================================================================
// It re-canonicalises. It does not validate.
// ============================================================================
//
// Asking "is this string canonical" would accept a canonical form of the WRONG
// HOST — which is exactly what a bug in Core's canonicalisation produces, and
// three sessions of scope findings say to expect one. So the runtime runs the
// same function on its own machine and requires its answer to EQUAL what
// arrived. A disagreement means the value was mutated in transit, or Core
// skipped the step, or Core's step produced something else; all three are
// things a check of Core's homework cannot see.
//
// One function run twice is not two implementations. What makes this the second
// enforcement site ADR-024 requires is that the computation is independent and
// its result is allowed to disagree.
func (h *engineHost) authorise(raw string) (bool, string) {
	c, ok := target.Matches(raw)
	if !ok {
		return false, "target is not in canonical form: " + raw
	}
	return scope.Permits(c, h.allowed, h.exclusions)
}

// start spawns the engine and hands it the job.
//
// Every target is authorised first. A refusal returns ErrOutOfScope and no
// process is created, so a target the runtime will not permit is never even
// named to something that could act on it.
func (h *engineHost) start(ctx context.Context, targets []enginewire.Target, budget engineBudget) error {
	// Refuse outright if a stop already arrived. stop() records the request even
	// when there is no process yet, precisely so this check can see it.
	h.mu.Lock()
	stopped := h.stopRequested
	h.mu.Unlock()
	if stopped {
		return errStopBeforeStart
	}
	if err := ctx.Err(); err != nil {
		return errStopBeforeStart
	}

	for _, t := range targets {
		if ok, why := h.authorise(t.Value); !ok {
			return fmt.Errorf("%w: task %s target %q: %s", ErrOutOfScope, t.TaskID, t.Value, why)
		}
	}

	// No ctx on the command, deliberately. exec.CommandContext kills with
	// SIGKILL on cancellation, which skips the SIGTERM grace ADR-027 requires
	// and gives the engine no chance to finish the observation in hand. Stop()
	// owns the lifecycle instead.
	// #nosec G204 -- h.binary is CVAP_SP_ENGINE_BINARY, operator configuration
	// read from the environment at startup. Nothing from the wire reaches it:
	// targets travel as JSON on stdin, never as argv, and there is no shell.
	// An operator who can set this variable can already run anything as this
	// uid.
	cmd := exec.Command(h.binary)
	cmd.Env = engineEnv()
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// Its own process group, so a stop reaches anything the engine spawned.
		// Signalling the pid alone leaves grandchildren running — which for a
		// real engine is the scanner still sending packets after the kill
		// switch fired, well outside ADR-024's 10-second bound.
		Setpgid: true,
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("scanpoint: engine stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("scanpoint: engine stdout: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("scanpoint: engine stderr: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("scanpoint: engine start: %w", err)
	}

	h.cmd = cmd
	h.in = stdin
	h.out = enginewire.NewReader(stdout)
	h.wire = enginewire.NewWriter(stdin)

	// An engine's stderr is diagnostic text from a process parsing hostile
	// input. Logged at debug and bounded by the pipe, never interpreted.
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := stderrPipe.Read(buf)
			if n > 0 {
				h.log.Debug("engine stderr",
					slog.String("job_id", h.jobID),
					slog.String("line", string(buf[:n])))
			}
			if err != nil {
				return
			}
		}
	}()

	return h.wire.WriteTo(enginewire.ToEngine{
		Kind:                   enginewire.KindJob,
		JobID:                  h.jobID,
		Targets:                targets,
		RateBudgetPPS:          budget.RatePPS,
		ConnectTimeoutMS:       budget.ConnectTimeoutMS,
		MaxConcurrentPerTarget: budget.MaxConcurrentPerTarget,
	})
}

// engineBudget is this engine's slice of the runtime's allocation (ADR-027).
//
// A slice, not the platform ceiling: engines do not read the ceiling and do not
// coordinate with each other, so the aggregate is bounded by what the runtime
// hands out rather than by cooperation. With one engine per job the slice is the
// job's whole allowance; the shape is what matters before there are two.
type engineBudget struct {
	RatePPS                uint32
	ConnectTimeoutMS       uint32
	MaxConcurrentPerTarget uint32
}

// pump reads until the engine's stdout closes, answering what it asks.
func (h *engineHost) pump() {
	for {
		msg, err := h.out.ReadFrom()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			// A malformed line is the engine's fault and ends the exchange.
			// Reading on would mean guessing at a framing we no longer trust.
			h.log.Warn("engine sent a message the runtime could not parse",
				slog.String("job_id", h.jobID), slog.Any("error", err))
			return
		}

		switch msg.Kind {
		case enginewire.KindObservation:
			if msg.Observation != nil {
				h.mu.Lock()
				n := len(msg.Observation.Payload) + 128
				if len(h.observations) >= MaxJobObservations ||
					h.observedBytes+n > MaxJobObservationBytes {
					if !h.truncated {
						h.truncated = true
						h.log.Error("engine exceeded the per-job observation bound; truncating",
							slog.String("job_id", h.jobID),
							slog.Int("observations", len(h.observations)),
							slog.Int("bytes", h.observedBytes))
					}
					h.mu.Unlock()
					continue
				}
				h.observations = append(h.observations, *msg.Observation)
				h.observedBytes += n
				h.mu.Unlock()
			}

		case enginewire.KindAuthorise:
			// ADR-027's mid-scan discovery path. The engine does not proceed
			// until this answer arrives, and a refusal is final.
			//
			// Once a stop is under way every answer is a refusal, whatever the
			// scope says. The grace window is for finishing the observation in
			// hand, not for starting work on a target the engine had not
			// touched yet.
			h.mu.Lock()
			stopped := h.stopRequested
			h.mu.Unlock()

			ok, why := false, "the job is stopping"
			if !stopped {
				ok, why = h.authorise(msg.Target)
			}
			if !ok {
				h.log.Warn("engine asked about a target it may not touch; refused",
					slog.String("job_id", h.jobID),
					slog.String("target", msg.Target),
					slog.String("reason", why))
			}
			if err := h.wire.WriteTo(enginewire.ToEngine{
				Kind:      enginewire.KindAuthorised,
				Target:    msg.Target,
				Permitted: ok,
				// The REASON does not travel. It names the rule that matched —
				// "excluded by scope rule 10.0.0.0/8" — and an engine that can
				// ask repeatedly would read the customer's exclusion list back
				// one target at a time. Engines hold no scope data, and that
				// has to include what they can infer from an answer.
				Reason: "",
			}); err != nil {
				return
			}

		case enginewire.KindSent:
			h.mu.Lock()
			h.sent += msg.Count
			h.mu.Unlock()

		case enginewire.KindDone:
			h.mu.Lock()
			h.sawDone = true
			h.mu.Unlock()
		}
	}
}

// stop is SIGTERM, then SIGKILL after grace (ADR-027).
//
// Signals go to the process GROUP — the negative pid — so anything the engine
// spawned goes with it. Both are best-effort: a process that has already exited
// returns ESRCH, which is the outcome we wanted.
// MaxStopGrace is ADR-024's propagation bound, enforced at the receiver.
//
// CancelJob.grace_ms is an operator lever — dispatch.proto says setting it lets
// an operator "cancel an intrusive job harder without a fleet redeploy" — and it
// arrives from the network. ADR-024's table marks kill propagation "within 10 s,
// not adjustable", and the field's own comment says it is "still bounded by
// ADR-024's 10 s propagation guarantee". Nothing bounded it. Core sends 5000
// today, so this was an unimplemented receiver-side MUST rather than a live
// overrun; the receiver is the only place it can be enforced.
const MaxStopGrace = 9 * time.Second

func (h *engineHost) stop(grace time.Duration) {
	// Recorded even when there is no process yet, so start() can refuse.
	h.mu.Lock()
	h.stopRequested = true
	h.mu.Unlock()

	if grace > MaxStopGrace || grace <= 0 {
		grace = MaxStopGrace
	}

	if h.cmd == nil || h.cmd.Process == nil {
		return
	}
	pgid := -h.cmd.Process.Pid

	_ = syscall.Kill(pgid, syscall.SIGTERM)

	// Closing stdin is a second, gentler signal: an engine blocked reading it
	// sees EOF. It costs nothing and it covers an engine that ignores SIGTERM
	// but not a closed pipe.
	if h.in != nil {
		_ = h.in.Close()
	}

	// Waits on wait()'s reaper rather than reaping itself. Two reapers raced
	// for one child, and the loser signalled a pid the kernel had released —
	// see the comment on the field.
	select {
	case <-h.reaped:
		return
	case <-time.After(grace):
	}

	h.mu.Lock()
	reaped := h.hasReaped
	h.mu.Unlock()
	if reaped {
		return
	}
	h.log.Warn("engine did not exit within the grace window; killing",
		slog.String("job_id", h.jobID),
		slog.Duration("grace", grace))
	_ = syscall.Kill(pgid, syscall.SIGKILL)
}

// wait reaps the process and classifies how it ended.
func (h *engineHost) wait() EngineOutcome {
	if h.cmd == nil {
		close(h.reaped)
		return EngineFailed
	}
	err := h.cmd.Wait()
	h.mu.Lock()
	h.hasReaped = true
	h.mu.Unlock()
	close(h.reaped)

	h.mu.Lock()
	requested, done := h.stopRequested, h.sawDone
	h.mu.Unlock()

	if requested {
		// We asked. Whatever the exit status, the reason belongs to the caller
		// that asked — a job killed by the kill switch is KILLED, not
		// ENGINE_FAILURE, and reporting the latter would send an operator to
		// look at a crash that did not happen.
		return EngineStopped
	}
	if err != nil {
		h.log.Error("engine process died",
			slog.String("job_id", h.jobID), slog.Any("error", err))
		return EngineFailed
	}
	if !done {
		// Exit 0 without the done message: stdout closed early, or the engine
		// returned before finishing its targets. Treated as a failure rather
		// than a completion, because the alternative is reporting a partial
		// scan as a whole one — under-scanning that looks like a clean run is
		// the worst failure this system has, since the customer acts on it.
		h.log.Error("engine exited without reporting done",
			slog.String("job_id", h.jobID))
		return EngineFailed
	}
	return EngineCompleted
}

// results returns what the engine produced, how much it says it sent, and
// whether anything was dropped at the bound.
func (h *engineHost) results() (obs []enginewire.Observation, sent uint32, truncated bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]enginewire.Observation(nil), h.observations...), h.sent, h.truncated
}
