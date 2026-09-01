package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ActorType mirrors the actor_type enum.
type ActorType string

const (
	ActorUser      ActorType = "user"
	ActorScanPoint ActorType = "scan_point"
	ActorSystem    ActorType = "system"
)

// AuditEvent is one record of something having happened.
//
// Execution-plan §5 requires an event for every credential release, scope
// change, policy edit and scan start; enrollment and rotation are here too,
// because the certificate fingerprint is the scan point's identity in this log
// (ADR-018) and an identity changing hands is exactly what an auditor asks about.
//
// ActorID and ResourceID are deliberately NOT foreign keys in the schema: an
// audit record must outlive the rows it describes, and an ON DELETE SET NULL
// would quietly erase who did something.
type AuditEvent struct {
	ID           uuid.UUID
	ActorID      *uuid.UUID
	ActorType    ActorType
	Action       string
	ResourceType string
	ResourceID   *uuid.UUID
	Detail       map[string]any
	OccurredAt   time.Time
}

type AuditEvents struct{}

// Record appends an event.
//
// Detail is marshalled here rather than by the caller so there is one place to
// look when asking what ends up in the log. Callers MUST NOT put credential
// material in it: the audit log is widely readable by design, and a token or a
// secret placed here is a secret published rather than recorded. Enrollment puts
// a token_id in Detail, never a token.
func (AuditEvents) Record(ctx context.Context, c *Conn, e AuditEvent) error {
	detail := []byte(`{}`)
	if e.Detail != nil {
		b, err := json.Marshal(e.Detail)
		if err != nil {
			return fmt.Errorf("store: marshal audit detail: %w", err)
		}
		detail = b
	}

	const q = `
		INSERT INTO audit_events
		    (tenant_id, actor_id, actor_type, action, resource_type, resource_id, detail)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := c.Exec(ctx, q, c.Tenant().UUID(), e.ActorID, string(e.ActorType),
		e.Action, e.ResourceType, e.ResourceID, detail)
	return mapError(err)
}

// ListByResource returns what happened to one resource, newest first.
func (AuditEvents) ListByResource(ctx context.Context, c *Conn, resourceType string, resourceID uuid.UUID, limit int) ([]AuditEvent, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	const q = `
		SELECT audit_event_id, actor_id, actor_type, action, resource_type,
		       resource_id, detail, occurred_at
		  FROM audit_events
		 WHERE tenant_id = $1 AND resource_type = $2 AND resource_id = $3
		 ORDER BY occurred_at DESC
		 LIMIT $4`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), resourceType, resourceID, limit)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		var raw []byte
		if err := rows.Scan(&e.ID, &e.ActorID, &e.ActorType, &e.Action,
			&e.ResourceType, &e.ResourceID, &raw, &e.OccurredAt); err != nil {
			return nil, mapError(err)
		}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &e.Detail)
		}
		out = append(out, e)
	}
	return out, mapError(rows.Err())
}
