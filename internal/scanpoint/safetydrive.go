package scanpoint

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/effaaykhan/cvap/internal/enginewire"
)

// ============================================================================
// The seam make safety's full form drives the RUNTIME through, not the engine.
// ============================================================================
//
// The narrow safety gate runs an engine binary directly and compares its egress
// against lab/scope.txt. That measures the engine, which holds no scope check at
// all — an engine constructs no targets and gets a vote on none (ADR-027). The
// scan-point-side enforcement of ADR-024 lives HERE, in engineHost.authorise: the
// pre-send loop over assigned targets and the mid-scan KindAuthorise answer for a
// target an engine discovered. The §6.3 cases — an exclusion overlapping an
// allow, a CIDR boundary, a redirect to an out-of-scope host — are decided by
// that code and by nothing the engine runs, so a gate that never instantiates it
// cannot measure them.
//
// SafetyDrive runs ONE job through the runtime's real send path — newEngineHost,
// then start (which authorises every target before the process exists), then pump
// (which answers KindAuthorise for discovered targets) and wait — spawning the
// real engine binary.
//
// It is NOT a second implementation of the two things that decide whether and how
// much leaves: SCOPE goes through the same start → authorise → target.Matches +
// scope.Permits onAssignment runs, so a target it withholds is one the runtime
// withholds; and the RATE / FRAGILE / PROBE budget goes through the same
// clampToBudget job.budget uses, so the rate ceiling, the fragile rate and
// concurrency caps and the fragile/safe probe suppression are the runtime's, not
// a copy. The one thing it does NOT reproduce is the corpus resolution and the
// signed-pack policy (applyProbePolicy) — a caller supplies probes directly — so
// a probe-corpus assertion belongs in the engine-direct phases, not here.
//
// It exists so make safety can put the scope machinery on a wire; run
// scan-safety-auditor on any change to it, as for the rest of this package.

// SafetyJob is one job for SafetyDrive: the authorised scope this runtime will
// enforce, the targets to hand the engine, and the engine budget.
type SafetyJob struct {
	JobID      string   `json:"job_id"`
	Allowed    []string `json:"allowed"`
	Exclusions []string `json:"exclusions"`

	Targets []enginewire.Target `json:"targets"`

	RatePPS                uint32 `json:"rate_budget_pps"`
	ConnectTimeoutMS       uint32 `json:"connect_timeout_ms"`
	MaxConcurrentPerTarget uint32 `json:"max_concurrent_per_target"`

	SafetyMode       string             `json:"safety_mode"`
	Probes           []enginewire.Probe `json:"probes,omitempty"`
	BannerMatches    []enginewire.Match `json:"banner_matches,omitempty"`
	MaxProbesPerPort uint32             `json:"max_probes_per_port,omitempty"`

	// StopAfterMS, when >0, stops the engine that many milliseconds after it
	// starts, through the same engineHost.stop the runtime's self-abort uses
	// (SIGTERM then SIGKILL after a grace). It exists for the §6.3
	// scope-changed-mid-scan case: an in-flight scan is halted and the capture
	// must show egress ceasing, which is the wire consequence of ADR-051's
	// renewal refusal. The trigger — a narrowing turning into a lost lease — is
	// asserted in internal/dispatch; this is the half that reaches a wire.
	StopAfterMS uint32 `json:"stop_after_ms,omitempty"`
}

// SafetyResult is what SafetyDrive reports for diagnostics. The gate's assertion
// is the packet capture, not this — but Refused distinguishes "the runtime
// refused the whole job on scope" (no engine, no packets, the ADR-024 site-two
// halt) from "the engine ran," which the capture alone cannot, because both look
// like an absence of packets to a forbidden address.
type SafetyResult struct {
	Refused      bool                     `json:"refused"`
	RefusedError string                   `json:"refused_error,omitempty"`
	Outcome      string                   `json:"outcome,omitempty"`
	Sent         uint32                   `json:"sent"`
	Observations []enginewire.Observation `json:"observations,omitempty"`
}

// SafetyDrive runs one job through the real send-path scope check and the real
// engine binary. A returned Refused=true is the whole-job scope halt
// (ErrOutOfScope); any other error is a harness failure, not a scope decision.
func SafetyDrive(ctx context.Context, log *slog.Logger, binary string, j SafetyJob) (SafetyResult, error) {
	h := newEngineHost(log, binary, j.JobID, j.Allowed, j.Exclusions)

	// The SAME ADR-024 clamp job.budget applies, so the harness cannot drive the
	// real engine past a ceiling the runtime would hold — a fragile target here
	// gets the 10 pps rate cap, the serialised concurrency cap and no probes,
	// exactly as in production.
	var anyFragile bool
	for _, t := range j.Targets {
		if t.Fragile {
			anyFragile = true
			break
		}
	}
	budget := clampToBudget(clampInputs{
		Rate: j.RatePPS,
		// A SafetyJob carries no lowered fragile rate; 0 means unspecified, so the
		// platform fragile ceiling (PlatformFragileRatePPS) applies to a fragile
		// target — which is exactly ADR-024 control 3's "regardless of policy".
		FragileRate: 0,
		Timeout:     j.ConnectTimeoutMS,
		Concurrency: j.MaxConcurrentPerTarget,
		SafetyMode:  j.SafetyMode,
		AnyFragile:  anyFragile,
		Probes:      j.Probes,
	})
	budget.BannerMatches = j.BannerMatches
	if j.MaxProbesPerPort != 0 {
		budget.MaxProbesPerPort = j.MaxProbesPerPort
	}

	if err := h.start(ctx, j.Targets, budget); err != nil {
		if errors.Is(err, ErrOutOfScope) {
			// Site two refused the whole job: no engine spawned, no packet sent.
			// This is a pass for a case whose forbidden target was among the
			// assignment, and the capture will (correctly) show nothing to it.
			return SafetyResult{Refused: true, RefusedError: err.Error()}, nil
		}
		return SafetyResult{}, err
	}

	// ADR-051's wire half: halt the in-flight engine through the same stop the
	// runtime's self-abort uses, so the capture shows egress ceasing. pump()
	// returns when the engine's stdout closes on SIGTERM, so the stop is driven
	// from a goroutine while pump reads.
	if j.StopAfterMS > 0 {
		go func() {
			time.Sleep(time.Duration(j.StopAfterMS) * time.Millisecond)
			h.stop(EngineStopGrace)
		}()
	}

	h.pump()
	outcome := h.wait()
	obs, sent, _ := h.results()
	return SafetyResult{
		Outcome:      outcome.String(),
		Sent:         sent,
		Observations: obs,
	}, nil
}
