package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ScanStatus mirrors the scan_status enum.
type ScanStatus string

const (
	ScanPending   ScanStatus = "pending"
	ScanPlanning  ScanStatus = "planning"
	ScanRunning   ScanStatus = "running"
	ScanCompleted ScanStatus = "completed"
	ScanFailed    ScanStatus = "failed"
	ScanCancelled ScanStatus = "cancelled"
	ScanKilled    ScanStatus = "killed"
)

// ErrSafetyModeAbovePolicy means a scan asked for more than its policy permits.
//
// The policy is the CEILING and the scan opts in beneath it (ADR-021). A scan
// under a safe policy cannot make itself intrusive, and the refusal is an error
// rather than a silent downgrade: a caller that asked for intrusive and got safe
// without being told would report a scan it did not run.
var ErrSafetyModeAbovePolicy = errors.New("store: scan safety mode exceeds its policy")

// ErrScanAlreadyStarted means the scan is past the point where its mode is a
// choice.
var ErrScanAlreadyStarted = errors.New("store: scan safety mode can only be set before the scan starts")

type Scans struct{}

// SetSafetyMode records ADR-021's per-scan opt-in, with the audit event.
//
// ============================================================================
// The policy sets the ceiling; the scan must opt in beneath it.
// ============================================================================
//
// ADR-021 makes safe the default for every policy and requires intrusive to be
// an explicit per-scan opt-in with an audit event. Without a per-scan column
// there was no opt-in to make: one policy flipped to intrusive standing-
// authorised every scan ever bound to it, including scheduled ones nobody looked
// at again. A policy left on intrusive after a test window is the exact failure
// the ADR was written against.
//
// Three properties, and each is here because its absence is a way to lose the
// control:
//
//   - The ceiling is checked in the UPDATE's own predicate, so it cannot be
//     raced past by a concurrent policy edit within this transaction's snapshot.
//     It is checked AGAIN in dispatch when constraints are built, because a
//     ceiling enforced in one place is decorative.
//   - Only a scan that has not started may be set. Escalating a running scan
//     would apply to its queued jobs and not to the ones already dispatched —
//     constraints are computed at claim time and never re-pushed — so it would
//     be a half-applied escalation reported as a whole one. Cancellation is the
//     lever for a running scan.
//   - The audit event is written in the SAME transaction. An opt-in recorded
//     without its event, or an event without the opt-in, is worse than either
//     alone, and the ADR asks for both.
//
// Safe selections are recorded too. A log that only holds the dangerous choice
// cannot show that the safe one was made deliberately, and "no event" would then
// mean both "nobody chose" and "somebody chose safe".
//
// Nothing calls this yet: the operator API is a later session. The path is
// unreachable and correct, which is the right state for it — the alternative is
// a column with no writer and no rule about who may write it.
func (Scans) SetSafetyMode(ctx context.Context, c *Conn, scanID uuid.UUID, mode SafetyMode, actor *uuid.UUID) error {
	switch mode {
	case SafetySafe, SafetyIntrusive:
	default:
		return fmt.Errorf("store: unknown safety mode %q", mode)
	}

	// The ceiling, in the predicate: 'safe' is always beneath a policy, and
	// 'intrusive' requires a policy that permits it.
	// $3 is pinned to text at every use. Without the casts Postgres infers the
	// parameter's type from the first context it appears in, and the two uses
	// here want different ones — an enum in the SET and a string in the
	// comparison.
	const q = `
		UPDATE scans s
		   SET safety_mode = $3::text::safety_mode
		  FROM scan_policies p
		 WHERE s.tenant_id = $1 AND s.scan_id = $2
		   AND p.tenant_id = s.tenant_id AND p.policy_id = s.policy_id
		   AND s.status IN ('pending', 'planning')
		   AND ($3::text = 'safe' OR p.safety_mode = 'intrusive')
		RETURNING p.policy_id, p.safety_mode`

	var policyID uuid.UUID
	var policyMode SafetyMode
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), scanID, string(mode)).Scan(&policyID, &policyMode)
	if err != nil {
		if !errors.Is(mapError(err), ErrNotFound) {
			return mapError(err)
		}
		// Refused. The read below chooses the message ONLY — the decision was
		// already made by the conditional UPDATE matching nothing.
		return (Scans{}).refusalReason(ctx, c, scanID, mode)
	}

	id := scanID
	return (AuditEvents{}).Record(ctx, c, AuditEvent{
		ActorID:      actor,
		ActorType:    ActorUser,
		Action:       "scan.safety_mode_selected",
		ResourceType: "scan",
		ResourceID:   &id,
		Detail: map[string]any{
			"safety_mode":        string(mode),
			"policy_id":          policyID.String(),
			"policy_safety_mode": string(policyMode),
		},
	})
}

// refusalReason turns "the UPDATE matched nothing" into something an operator
// can act on. It never decides anything.
func (Scans) refusalReason(ctx context.Context, c *Conn, scanID uuid.UUID, want SafetyMode) error {
	const q = `
		SELECT s.status, p.safety_mode
		  FROM scans s
		  JOIN scan_policies p ON p.tenant_id = s.tenant_id AND p.policy_id = s.policy_id
		 WHERE s.tenant_id = $1 AND s.scan_id = $2`

	var status ScanStatus
	var policyMode SafetyMode
	if err := c.QueryRow(ctx, q, c.Tenant().UUID(), scanID).Scan(&status, &policyMode); err != nil {
		return mapError(err)
	}
	switch {
	case status != ScanPending && status != ScanPlanning:
		return fmt.Errorf("%w: scan %s is %s", ErrScanAlreadyStarted, scanID, status)
	case want == SafetyIntrusive && policyMode != SafetyIntrusive:
		return fmt.Errorf("%w: scan %s asked for intrusive under a %s policy",
			ErrSafetyModeAbovePolicy, scanID, policyMode)
	default:
		// Both predicates hold on this read but the UPDATE matched nothing, so
		// something changed underneath it. Reported rather than retried.
		return ErrNotFound
	}
}

// Scan is one scan, as an operator sees it.
type Scan struct {
	ID          uuid.UUID
	PolicyID    uuid.UUID
	RequestedBy *uuid.UUID
	ScanType    string
	Status      ScanStatus
	SafetyMode  SafetyMode
	CreatedAt   time.Time
	StartedAt   *time.Time
	CompletedAt *time.Time
}

// ScanTarget is one authorised target of a scan, as written at creation.
//
// Value is the operator's string, stored as they wrote it. It is NOT the string
// a scan point receives: decomposition canonicalises (ADR-044) and writes the
// result to scan_tasks.task_target. Keeping the original here is what lets an
// operator recognise what they authorised, and what makes
// authorization_verified a statement about something they can read.
type ScanTarget struct {
	ID         uuid.UUID
	Type       string
	Value      string
	Authorized bool
	VerifiedAt *time.Time
	CreatedAt  time.Time
}

// ErrTargetNotAuthorized means a scan was asked to run against a target whose
// authorization_verified is false.
//
// Execution-plan §8 risk 6: scanning without authorisation is legal exposure.
// The column defaults false and nothing may decompose a target that still is.
var ErrTargetNotAuthorized = errors.New("store: scan target has no verified authorization")

// ErrScanNotCancellable means the scan has already finished.
var ErrScanNotCancellable = errors.New("store: scan is not in a cancellable state")

// Create records a scan and its targets in one transaction.
//
// safety_mode is NOT settable here. It defaults to safe and moves only through
// SetSafetyMode, which checks the policy ceiling and writes the ADR-021 audit
// event — a creation path that accepted a mode would be a second way to opt in,
// and the one without the audit event.
func (Scans) Create(ctx context.Context, c *Conn, policyID uuid.UUID, scanType string, requestedBy *uuid.UUID, targets []ScanTarget) (*Scan, error) {
	if scanType == "" {
		return nil, fmt.Errorf("store: scan_type is required")
	}
	if len(targets) == 0 {
		// A scan with no targets is not an empty scan; it is a scan that would
		// complete instantly and report a clean result over nothing. ADR-037's
		// reasoning about permission lists applies to the same shape of mistake.
		return nil, fmt.Errorf("store: a scan needs at least one target")
	}

	const insertScan = `
		INSERT INTO scans (tenant_id, policy_id, requested_by, scan_type)
		VALUES ($1, $2, $3, $4)
		RETURNING scan_id, policy_id, requested_by, scan_type, status, safety_mode,
		          created_at, started_at, completed_at`

	var s Scan
	err := c.QueryRow(ctx, insertScan, c.Tenant().UUID(), policyID, requestedBy, scanType).Scan(
		&s.ID, &s.PolicyID, &s.RequestedBy, &s.ScanType, &s.Status, &s.SafetyMode,
		&s.CreatedAt, &s.StartedAt, &s.CompletedAt)
	if err != nil {
		return nil, mapError(err)
	}

	const insertTarget = `
		INSERT INTO scan_targets
			(tenant_id, scan_id, target_type, target_value, authorization_verified, verified_at)
		VALUES ($1, $2, $3::text::scan_target_type, $4, $5, CASE WHEN $5 THEN now() ELSE NULL END)`

	for _, t := range targets {
		if _, err := c.Exec(ctx, insertTarget, c.Tenant().UUID(), s.ID, t.Type, t.Value, t.Authorized); err != nil {
			return nil, mapError(err)
		}
	}
	return &s, nil
}

// Get returns one scan.
func (Scans) Get(ctx context.Context, c *Conn, scanID uuid.UUID) (*Scan, error) {
	const q = `
		SELECT scan_id, policy_id, requested_by, scan_type, status, safety_mode,
		       created_at, started_at, completed_at
		  FROM scans WHERE tenant_id = $1 AND scan_id = $2`

	var s Scan
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), scanID).Scan(
		&s.ID, &s.PolicyID, &s.RequestedBy, &s.ScanType, &s.Status, &s.SafetyMode,
		&s.CreatedAt, &s.StartedAt, &s.CompletedAt)
	if err != nil {
		return nil, mapError(err)
	}
	return &s, nil
}

// Targets returns a scan's targets as the operator wrote them.
func (Scans) Targets(ctx context.Context, c *Conn, scanID uuid.UUID) ([]ScanTarget, error) {
	const q = `
		SELECT target_id, target_type::text, target_value, authorization_verified,
		       verified_at, created_at
		  FROM scan_targets WHERE tenant_id = $1 AND scan_id = $2
		 ORDER BY created_at, target_id`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), scanID)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []ScanTarget
	for rows.Next() {
		var t ScanTarget
		if err := rows.Scan(&t.ID, &t.Type, &t.Value, &t.Authorized, &t.VerifiedAt, &t.CreatedAt); err != nil {
			return nil, mapError(err)
		}
		out = append(out, t)
	}
	return out, mapError(rows.Err())
}

// List returns a page of scans, newest first.
//
// Keyset pagination on (created_at, scan_id) rather than OFFSET: an operator
// paging through a list while scans are being created would otherwise see rows
// shift under them, and OFFSET on a large table degrades in a way that shows up
// only in the deployments with the most scans.
func (Scans) List(ctx context.Context, c *Conn, status ScanStatus, limit int, beforeTime *time.Time, beforeID *uuid.UUID) ([]Scan, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	const q = `
		SELECT scan_id, policy_id, requested_by, scan_type, status, safety_mode,
		       created_at, started_at, completed_at
		  FROM scans
		 WHERE tenant_id = $1
		   AND ($2::text IS NULL OR status = $2::text::scan_status)
		   AND ($3::timestamptz IS NULL OR (created_at, scan_id) < ($3::timestamptz, $4::uuid))
		 ORDER BY created_at DESC, scan_id DESC
		 LIMIT $5`

	var statusArg *string
	if status != "" {
		v := string(status)
		statusArg = &v
	}

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), statusArg, beforeTime, beforeID, limit)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []Scan
	for rows.Next() {
		var s Scan
		if err := rows.Scan(&s.ID, &s.PolicyID, &s.RequestedBy, &s.ScanType, &s.Status,
			&s.SafetyMode, &s.CreatedAt, &s.StartedAt, &s.CompletedAt); err != nil {
			return nil, mapError(err)
		}
		out = append(out, s)
	}
	return out, mapError(rows.Err())
}

// Cancel stops a scan, and is the writer ADR-024 control 4 was missing.
//
// ============================================================================
// scans.status = 'cancelled' now has a writer.
// ============================================================================
//
// Everything downstream of this column was built and correct in session 8e and
// unreachable: Jobs.Claim excludes jobs whose scan is stopped, CancellableFor
// finds the in-flight ones, and dispatch sends CancelJob to the scan points
// holding them. What was missing was the operator being able to say so.
//
// Cancelling sets the SCAN's status and nothing else. It does not touch
// scan_jobs: the queued ones stop being claimable through Jobs.Claim's own
// predicate, and the running ones are reached by CancellableFor on the next
// dispatch pass, which sends CancelJob naming the lease epoch. Marking jobs here
// as well would be a second source of truth about whether something is stopping,
// and the two would disagree the first time a job terminated between the two
// writes.
//
// A completed scan is refused rather than silently accepted. "Cancel" on
// something that already finished did not do what the operator asked, and
// reporting success would tell them they stopped a scan whose packets had
// already been sent.
func (Scans) Cancel(ctx context.Context, c *Conn, scanID uuid.UUID, actor *uuid.UUID, reason string) error {
	const q = `
		UPDATE scans
		   SET status = 'cancelled', completed_at = now()
		 WHERE tenant_id = $1 AND scan_id = $2
		   AND status IN ('pending', 'planning', 'running')
		RETURNING scan_id`

	var got uuid.UUID
	if err := c.QueryRow(ctx, q, c.Tenant().UUID(), scanID).Scan(&got); err != nil {
		if !errors.Is(mapError(err), ErrNotFound) {
			return mapError(err)
		}
		// The UPDATE decided. This read only chooses the message.
		var status ScanStatus
		const check = `SELECT status FROM scans WHERE tenant_id = $1 AND scan_id = $2`
		if err := c.QueryRow(ctx, check, c.Tenant().UUID(), scanID).Scan(&status); err != nil {
			return mapError(err)
		}
		return fmt.Errorf("%w: scan %s is %s", ErrScanNotCancellable, scanID, status)
	}

	id := scanID
	return (AuditEvents{}).Record(ctx, c, AuditEvent{
		ActorID:      actor,
		ActorType:    ActorUser,
		Action:       "scan.cancelled",
		ResourceType: "scan",
		ResourceID:   &id,
		Detail:       map[string]any{"reason": reason},
	})
}

// PlannedTask is one task decomposition produced, ready to be written.
//
// Target is CANONICAL (ADR-044). This type is the boundary the canonicalisation
// has to have crossed by: nothing in this package canonicalises, and nothing
// downstream of it does either — the scan point re-computes, which is a
// comparison rather than a repair.
type PlannedTask struct {
	Target   string
	TargetID *uuid.UUID
}

// Plan writes one job and its tasks.
//
// The job and its tasks are one statement pair in one transaction, because a job
// with no tasks is claimable, assignable and completes instantly against
// nothing — a clean result over work that was never planned, which is the
// under-scanning-that-looks-complete failure this codebase refuses everywhere.
func (Scans) Plan(ctx context.Context, c *Conn, scanID uuid.UUID, engine Engine, reassignSafe bool, tasks []PlannedTask) (uuid.UUID, error) {
	if len(tasks) == 0 {
		return uuid.Nil, fmt.Errorf("store: a job needs at least one task")
	}

	const insertJob = `
		INSERT INTO scan_jobs (tenant_id, scan_id, engine, reassign_safe)
		VALUES ($1, $2, $3::text::engine_kind, $4)
		RETURNING job_id`

	var jobID uuid.UUID
	if err := c.QueryRow(ctx, insertJob, c.Tenant().UUID(), scanID, string(engine), reassignSafe).Scan(&jobID); err != nil {
		return uuid.Nil, mapError(err)
	}

	const insertTask = `
		INSERT INTO scan_tasks (tenant_id, job_id, target_id, task_target)
		VALUES ($1, $2, $3, $4)`

	b := &Batch{}
	for _, t := range tasks {
		if t.Target == "" {
			return uuid.Nil, fmt.Errorf("store: a task needs a target")
		}
		b.Queue(insertTask, c.Tenant().UUID(), jobID, t.TargetID, t.Target)
	}
	br := c.SendBatch(ctx, b)
	for range tasks {
		if _, err := br.Exec(); err != nil {
			_ = br.Close()
			return uuid.Nil, mapError(err)
		}
	}
	if err := br.Close(); err != nil {
		return uuid.Nil, mapError(err)
	}
	return jobID, nil
}

// EngineForScanType maps a scan's type to the engine that runs it, and is the
// ONE place that mapping lives. Both the planner (deciding what to queue) and the
// API (deciding at creation whether any scan point can run it) ask this, so the
// two cannot disagree about which types are plannable — a scan the API accepts
// but the planner has no engine for is the silent non-result this centralisation
// exists to prevent. `scans.scan_type` is deliberately free text (engines are
// extensible); this is Core stating what it can actually plan today.
func EngineForScanType(scanType string) (Engine, bool) {
	switch scanType {
	case "discovery":
		return EngineDiscovery, true
	case "fingerprint":
		return EngineFingerprint, true
	case "rules":
		return EngineRules, true
	case "host":
		// Credentialed-host inventory (ADR-086/090, Phase 4). Plannable now that the
		// credhost engine emits `package` observations and correlation consumes them.
		return EngineHost, true
	default:
		return "", false
	}
}

// SetStatus moves a scan between statuses, guarded by the statuses it may move
// from.
//
// The guard is in the UPDATE's predicate rather than a read-then-write, so a
// scan cancelled between the two cannot be moved to running by a planner that
// checked a moment earlier. ErrNotFound means the scan was not in one of `from`
// — most often because an operator cancelled it, which is exactly the race the
// predicate exists for.
func (Scans) SetStatus(ctx context.Context, c *Conn, scanID uuid.UUID, from []ScanStatus, to ScanStatus) error {
	const q = `
		UPDATE scans
		   SET status = $3::text::scan_status,
		       started_at = CASE WHEN $3::text = 'running' AND started_at IS NULL
		                         THEN now() ELSE started_at END,
		       completed_at = CASE WHEN $3::text IN ('completed', 'failed', 'killed')
		                           THEN now() ELSE completed_at END
		 WHERE tenant_id = $1 AND scan_id = $2
		   AND status = ANY($4::text[]::scan_status[])
		RETURNING scan_id`

	froms := make([]string, 0, len(from))
	for _, f := range from {
		froms = append(froms, string(f))
	}

	var got uuid.UUID
	if err := c.QueryRow(ctx, q, c.Tenant().UUID(), scanID, string(to), froms).Scan(&got); err != nil {
		return mapError(err)
	}
	return nil
}

// PendingIDs lists scans waiting to be planned, oldest first.
//
// Oldest first, deliberately: a scan created an hour ago must not be starved by
// a stream of newer ones, which is what newest-first ordering plus a limit
// produces under load.
func (Scans) PendingIDs(ctx context.Context, c *Conn, limit int) ([]uuid.UUID, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	const q = `
		SELECT scan_id FROM scans
		 WHERE tenant_id = $1 AND status = 'pending'
		 ORDER BY created_at, scan_id
		 LIMIT $2`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), limit)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, mapError(err)
		}
		out = append(out, id)
	}
	return out, mapError(rows.Err())
}

// Fail marks a scan failed, with the reason in an audit event.
//
// For a scan that cannot be planned. It is a terminal state rather than a
// retry: the reasons planning refuses — an unattested target, a target with no
// canonical form, a range too large — are all things an operator must change,
// and a scan retried against the same rows would fail identically forever while
// looking like activity.
func (Scans) Fail(ctx context.Context, c *Conn, scanID uuid.UUID, reason string) error {
	const q = `
		UPDATE scans SET status = 'failed', completed_at = now()
		 WHERE tenant_id = $1 AND scan_id = $2
		   AND status IN ('pending', 'planning', 'running')
		RETURNING scan_id`

	var got uuid.UUID
	if err := c.QueryRow(ctx, q, c.Tenant().UUID(), scanID).Scan(&got); err != nil {
		return mapError(err)
	}
	id := scanID
	return (AuditEvents{}).Record(ctx, c, AuditEvent{
		ActorType:    ActorSystem,
		Action:       "scan.planning_failed",
		ResourceType: "scan",
		ResourceID:   &id,
		Detail:       map[string]any{"reason": reason},
	})
}

// SettleIfDone moves a running scan to completed or failed once none of its
// jobs is queued, assigned or running. Called on every job terminal, so a scan
// whose last job just ended settles in the same transaction.
//
// Nothing did this before: scans reached `running` at planning and stayed there
// forever after every job had finished, so an operator read thirty scans as in
// flight against a fleet that had long since gone quiet (S42, the deploy
// estate). completed when at least one job completed; failed when every job
// failed. A scan with no jobs at all is left alone — the planner owns that.
func (Scans) SettleIfDone(ctx context.Context, c *Conn, scanID uuid.UUID) (ScanStatus, error) {
	const q = `
		UPDATE scans s
		   SET status = CASE WHEN EXISTS (SELECT 1 FROM scan_jobs j WHERE j.tenant_id = s.tenant_id AND j.scan_id = s.scan_id AND j.status = 'completed')
		                     THEN 'completed'::scan_status ELSE 'failed'::scan_status END,
		       completed_at = now()
		 WHERE s.tenant_id = $1 AND s.scan_id = $2
		   AND s.status IN ('planning','running')
		   AND EXISTS (SELECT 1 FROM scan_jobs j WHERE j.tenant_id = s.tenant_id AND j.scan_id = s.scan_id)
		   AND NOT EXISTS (SELECT 1 FROM scan_jobs j WHERE j.tenant_id = s.tenant_id AND j.scan_id = s.scan_id
		                    AND j.status IN ('queued','assigned','running'))
		RETURNING s.status::text`
	var st string
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), scanID).Scan(&st)
	if err != nil {
		if mapped := mapError(err); errors.Is(mapped, ErrNotFound) {
			return "", nil // still has work in flight, or already settled
		}
		return "", mapError(err)
	}
	return ScanStatus(st), nil
}
