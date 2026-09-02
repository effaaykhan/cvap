package store

import (
	"context"
	"errors"
	"fmt"

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
