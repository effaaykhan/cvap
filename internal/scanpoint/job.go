package scanpoint

import (
	"context"
	"sync"
	"time"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
	"github.com/effaaykhan/cvap/internal/enginewire"
)

// job is one assignment this scan point is executing.
//
// The runtime's job table is the authority on what is running here, and that is
// what makes reconnect safe: an assignment for a job already in the table is
// never started a second time, whatever Core sends. See Runtime.onAssignment for
// the epoch rules.
type job struct {
	id string

	// epoch is guarded by mu: the receive loop writes it on a LeaseGrant while
	// abort and terminate goroutines read it.
	epoch        int64
	reassignSafe bool
	constraints  *scanpointv1.ScanConstraints
	tasks        []*scanpointv1.Task

	// host and cancel are built BEFORE the job enters the runtime's table and
	// before any goroutine runs, so the terminal path can never find them nil.
	//
	// They used to be assigned inside runJob, which raced its own caller: a
	// CancelJob or KillSwitch arriving on the very next message — which is
	// exactly how receiveLoop delivers them, back to back on one stream —
	// found both nil, stopped nothing, sent a JobTerminal and a CancelAck, and
	// then the spawn went ahead. The engine ran unsupervised, outside the job
	// table, unreachable by a second cancel or by the kill switch. Two
	// independent reviews reproduced it.
	host   *engineHost
	cancel context.CancelFunc

	mu sync.Mutex

	// creds is every credential this job has been issued, not just the last.
	//
	// A single pointer meant a second CredentialGrant replaced the first
	// without erasing it: the displaced material stayed resident for the life
	// of the process, and credentials_zeroised then answered about the
	// REPLACEMENT — so Core's audit recorded the invariant as satisfied. Worse
	// than reporting false, because Core only audits the absent case.
	creds []*Credential

	expires  time.Time
	aborting bool
	reason   scanpointv1.TerminationReason

	// once guards the whole terminal path. Lease loss, a CancelJob and a kill
	// switch race by construction — Core sends a kill and a cancellation for
	// the same scan, and a lease can lapse while both are in flight. First
	// caller wins and its reason is the one recorded; the others return
	// immediately rather than submitting a second time under a different one.
	once sync.Once
	done chan struct{}
}

// addCredential takes a new grant without losing the old one.
func (j *job) addCredential(c *Credential) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.creds = append(j.creds, c)
}

// zeroiseCredentials erases every credential this job has ever held (ADR-020).
func (j *job) zeroiseCredentials() {
	j.mu.Lock()
	creds := append([]*Credential(nil), j.creds...)
	j.mu.Unlock()
	for _, c := range creds {
		c.Zeroise()
	}
}

// credentialsZeroised answers over EVERYTHING the job held, which is what
// JobTerminal.credentials_zeroised claims and what Core audits.
func (j *job) credentialsZeroised() bool {
	j.mu.Lock()
	creds := append([]*Credential(nil), j.creds...)
	j.mu.Unlock()
	for _, c := range creds {
		if !c.Zeroised() {
			return false
		}
	}
	return true
}

// setEpoch and currentEpoch guard the field the receive loop writes and the
// abort goroutines read.
func (j *job) setEpoch(e int64) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.epoch = e
}

func (j *job) currentEpoch() int64 {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.epoch
}

func (j *job) setExpiry(t time.Time) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.expires = t
}

func (j *job) expiry() time.Time {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.expires
}

// leaseLapsed reports whether the lease is gone by this runtime's clock.
//
// Measured against expiry MINUS a safety margin, not against expiry. The
// deadline that matters is Core's, and Core may reassign the job the instant its
// own clock passes it. A runtime scanning until its own clock reached the same
// instant would still be sending packets while a second scan point started the
// same work — so it stops early, which costs a requeue and never costs duplicate
// execution.
func (j *job) leaseLapsed(now time.Time) bool {
	e := j.expiry()
	if e.IsZero() {
		return false
	}
	return now.After(e.Add(-LeaseSafetyMargin))
}

// beginAbort marks the job terminal and reports whether this caller owns it.
func (j *job) beginAbort(reason scanpointv1.TerminationReason) bool {
	owns := false
	j.once.Do(func() {
		j.mu.Lock()
		j.aborting = true
		j.reason = reason
		j.mu.Unlock()
		owns = true
	})
	return owns
}

// wireTargets converts the assignment's tasks into what an engine receives.
//
// fragile travels because the runtime allocates a smaller rate slice for it, not
// because the engine reads it as permission (ADR-024 control 3). No scope data
// travels at all: an engine that could evaluate scope would be a third
// enforcement site.
func (j *job) wireTargets() []enginewire.Target {
	out := make([]enginewire.Target, 0, len(j.tasks))
	for _, t := range j.tasks {
		out = append(out, enginewire.Target{
			TaskID:  t.GetTaskId(),
			Value:   t.GetTarget(),
			Fragile: t.GetFragile(),
		})
	}
	return out
}

// budget is this job's slice of the rate allowance.
//
// One engine per job today, so the slice is the whole allowance. The shape
// matters before there are two: ADR-027 requires the runtime to allocate rather
// than share, so that the aggregate is bounded by construction rather than by
// engines cooperating. fragile_rate_pps is the lower ceiling when any task in
// the job is fragile — the cap applies regardless of what the policy permits.
func (j *job) budget() engineBudget {
	c := j.constraints

	// min(what Core sent, what ADR-024 permits). Forwarding Core's number
	// verbatim made this site enforcement in name only: a Core with a planning
	// bug, or one running ahead of a months-old scan point, could raise a
	// ceiling the ADR says may only be lowered. Zero means Core sent nothing,
	// and the platform default applies rather than "no limit".
	rate := clampCeiling(c.GetMaxRatePerTarget(), PlatformMaxRatePerTarget)

	var anyFragile bool
	for _, t := range j.tasks {
		if t.GetFragile() {
			anyFragile = true
			// ADR-024 control 3: fragile caps rate REGARDLESS of what the
			// policy permits. The runtime holds the 10 pps number itself, so
			// the cap applies even when Core sends 0 or forgets the field —
			// which is the only way "regardless" can be true at this site.
			f := clampCeiling(c.GetFragileRatePps(), PlatformFragileRatePPS)
			if f < rate {
				rate = f
			}
			break
		}
	}

	// ========================================================================
	// A FRAGILE target gets no probes, whatever the mode says.
	// ========================================================================
	//
	// ADR-024 control 3 is that fragile "suppresses aggressive checks AND caps
	// rate". Only the rate half existed: probes were decided from safety_mode
	// alone, and Target.Fragile was read by nothing in the engine at all — a
	// packet-capture audit measured a HEAD request and a bare newline going to a
	// device marked fragile.
	//
	// Suppressed HERE rather than in the engine, for the reason the whole probe
	// mechanism is here: an engine cannot send what it was never handed, and a
	// flag it is trusted to honour is not the same guarantee.
	//
	// Whole-job rather than per-target, because probes travel once per job. That
	// is deliberately conservative — one fragile target costs the whole job its
	// probes, which loses some service identification and cannot harm anything.
	// Per-target probe sets would need the engine to hold a mapping, which is
	// more contract for a case chunking makes rare: a job is 32 targets from one
	// planning pass.
	//
	// Probes travel ONLY under an intrusive mode, and the emptiness is the
	// control rather than the mode string (ADR-021, and engineHost.start).
	//
	// The runtime holds the corpus, not the engine, for the same reason it holds
	// the rate budget: an engine cannot send what it was never handed, so safe
	// mode is not a branch inside the component with the socket. A bug there, or
	// a rule asking for a probe, has nothing to reach for.
	//
	// Note which way round the default falls. An unrecognised or absent mode is
	// NOT intrusive, so a Core that sent nothing, or a value this build does not
	// know, yields no probes — the same direction clampCeiling takes for an
	// absent rate.
	var probes []enginewire.Probe
	if c.GetSafetyMode() == SafetyIntrusive && !anyFragile {
		probes = ProbeCorpus()
	}

	return engineBudget{
		RatePPS:                rate,
		ConnectTimeoutMS:       clampCeiling(c.GetConnectTimeoutMs(), PlatformConnectTimeoutMS),
		MaxConcurrentPerTarget: clampCeiling(c.GetMaxConcurrentPerTarget(), PlatformMaxConcurrentPerTarget),
		SafetyMode:             c.GetSafetyMode(),
		Probes:                 probes,
	}
}

// clampCeiling takes the lower of a wire value and the platform ceiling,
// treating zero as "unset" rather than as "no limit".
//
// Zero is the dangerous reading: proto3 cannot distinguish an unset uint32 from
// a deliberate zero, and for a rate ceiling one of those two readings is
// "unlimited". The platform default is the only safe answer for an absent
// value, and a deliberate zero is not a rate anybody wants either.
func clampCeiling(sent, platform uint32) uint32 {
	if sent == 0 || sent > platform {
		return platform
	}
	return sent
}
