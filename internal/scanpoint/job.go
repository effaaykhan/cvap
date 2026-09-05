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

	// corpus is the fingerprint content in force for this job, resolved once at
	// startup rather than per job — a pack that changed mid-scan would make two
	// halves of one scan mean different things.
	//
	// Nil falls back to the built-in set, which is what a test constructing a
	// bare job gets and what a runtime with no pack configured runs.
	corpus *Corpus

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

	var anyFragile bool
	for _, t := range j.tasks {
		if t.GetFragile() {
			anyFragile = true
			break
		}
	}

	corpus := j.corpus
	if corpus == nil {
		// A test constructing a bare job, or a runtime that has not resolved one
		// yet. Rejections are dropped here rather than logged: LoadCorpus is the
		// path that reports them, and this fallback exists so a job never runs
		// with no corpus at all.
		corpus, _ = BuiltinCorpus()
	}

	b := clampToBudget(clampInputs{
		Rate:        c.GetMaxRatePerTarget(),
		FragileRate: c.GetFragileRatePps(),
		Timeout:     c.GetConnectTimeoutMs(),
		Concurrency: c.GetMaxConcurrentPerTarget(),
		SafetyMode:  c.GetSafetyMode(),
		AnyFragile:  anyFragile,
		// The runtime holds the corpus, not the engine: an engine cannot send a
		// probe it was never handed, so safe mode is not a branch inside the
		// component with the socket. clampToBudget decides whether these travel.
		Probes: corpus.Probes,
	})

	// Banner matches travel in EVERY mode, including safe: reading is not sending
	// — the bytes have already arrived by the time a rule looks at them — so
	// withholding them would cost identification and buy no safety. Probes are the
	// withheld half; that asymmetry is the whole safe/intrusive distinction and it
	// lives in clampToBudget.
	b.BannerMatches = corpus.BannerMatches
	return b
}

// clampInputs is what clampToBudget reduces to an engineBudget.
type clampInputs struct {
	Rate, FragileRate, Timeout, Concurrency uint32
	SafetyMode                              string
	AnyFragile                              bool
	Probes                                  []enginewire.Probe
}

// clampToBudget applies ADR-024's ceilings to what a caller asks for, and is the
// ONE place that decision lives.
//
// It is shared by job.budget (the production send path) and by SafetyDrive (the
// safety-gate harness) so the harness cannot claim to enforce a ceiling the
// runtime enforces while actually enforcing a different one — a harness that
// clamped rate differently from production would measure itself, not the product.
// It sets no BannerMatches or MaxProbesPerPort of its own beyond the platform
// cap; the caller supplies banner matches, which travel in every mode.
func clampToBudget(in clampInputs) engineBudget {
	// min(what was asked, what ADR-024 permits). Forwarding a number verbatim
	// makes a ceiling enforcement in name only: a planning bug, or a Core running
	// ahead of a months-old scan point, could raise a ceiling the ADR says may
	// only be lowered. Zero means nothing was sent, and the platform default
	// applies rather than "no limit".
	rate := clampCeiling(in.Rate, PlatformMaxRatePerTarget)
	if in.AnyFragile {
		// ADR-024 control 3: fragile caps rate REGARDLESS of what the policy
		// permits. The 10 pps number is held here, so the cap applies even when
		// the caller sends 0 or forgets the field — the only way "regardless" can
		// be true at this site.
		if f := clampCeiling(in.FragileRate, PlatformFragileRatePPS); f < rate {
			rate = f
		}
	}

	// A fragile target is SERIALISED as well as slowed: connection count is the
	// other lever and the one that tips a printer over.
	concurrency := clampCeiling(in.Concurrency, PlatformMaxConcurrentPerTarget)
	if in.AnyFragile && concurrency > PlatformFragileMaxConcurrent {
		concurrency = PlatformFragileMaxConcurrent
	}

	// ========================================================================
	// A FRAGILE target gets no probes, whatever the mode says; a SAFE job gets
	// none either. The emptiness is the control, not the mode string (ADR-021).
	// ========================================================================
	//
	// ADR-024 control 3 is that fragile "suppresses aggressive checks AND caps
	// rate". Suppressed here rather than in the engine, for the reason the whole
	// probe mechanism is here: an engine cannot send what it was never handed.
	// Whole-job rather than per-target — probes travel once per job — which is
	// conservative: one fragile target costs the job its probes and can harm
	// nothing. An unrecognised or absent mode is NOT intrusive, so it yields no
	// probes, the same direction clampCeiling takes for an absent rate.
	var probes []enginewire.Probe
	if in.SafetyMode == SafetyIntrusive && !in.AnyFragile {
		probes = in.Probes
	}

	return engineBudget{
		RatePPS:                rate,
		ConnectTimeoutMS:       clampCeiling(in.Timeout, PlatformConnectTimeoutMS),
		MaxConcurrentPerTarget: concurrency,
		SafetyMode:             in.SafetyMode,
		Probes:                 probes,
		MaxProbesPerPort:       PlatformMaxProbesPerPort,
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
