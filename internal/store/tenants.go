package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Persistence only. No business logic anywhere in this package: derivation of
// assets and findings from observations belongs to internal/control (ADR-006),
// and putting any of it here would put it below the layer that owns it.

// DeploymentMode is TENANT.deployment_mode. On-prem is one tenant row, not a
// separate code path or a build variant (ADR-017).
type DeploymentMode string

const (
	DeploymentSaaS   DeploymentMode = "saas"
	DeploymentOnPrem DeploymentMode = "onprem"
)

type TenantStatus string

const (
	TenantActive    TenantStatus = "active"
	TenantSuspended TenantStatus = "suspended"
	TenantClosed    TenantStatus = "closed"
)

type Tenant struct {
	ID             TenantID
	Name           string
	DeploymentMode DeploymentMode
	Status         TenantStatus
	CreatedAt      time.Time
}

// Tenants is a stateless repository. It takes a *Conn per call rather than
// holding one, so a repository value cannot outlive the transaction that made
// it valid, and cannot acquire a connection of its own.
type Tenants struct{}

// Create inserts the tenant the connection is already scoped to.
//
// Note the shape, which is not the obvious one: creating a tenant needs a
// tenant context, because the RLS policy on `tenants` has a WITH CHECK like
// every other table. So the caller generates the id, opens Write with it, and
// inserts a row whose tenant_id is that same id — which the policy permits. No
// unscoped path is needed, and none exists.
func (Tenants) Create(ctx context.Context, c *Conn, name string, mode DeploymentMode) (*Tenant, error) {
	const q = `
		INSERT INTO tenants (tenant_id, name, deployment_mode)
		VALUES ($1, $2, $3)
		RETURNING tenant_id, name, deployment_mode, status, created_at`

	var t Tenant
	var id uuid.UUID
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), name, string(mode)).
		Scan(&id, &t.Name, &t.DeploymentMode, &t.Status, &t.CreatedAt)
	if err != nil {
		return nil, mapError(err)
	}
	t.ID, err = NewTenantID(id)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// Get returns the connection's own tenant. There is no Get(id) taking an
// arbitrary tenant id: RLS would return nothing for any other value, so such a
// method would be a way to write code that looks like it works and never does.
func (Tenants) Get(ctx context.Context, c *Conn) (*Tenant, error) {
	const q = `
		SELECT tenant_id, name, deployment_mode, status, created_at
		  FROM tenants
		 WHERE tenant_id = $1`

	var t Tenant
	var id uuid.UUID
	err := c.QueryRow(ctx, q, c.Tenant().UUID()).
		Scan(&id, &t.Name, &t.DeploymentMode, &t.Status, &t.CreatedAt)
	if err != nil {
		return nil, mapError(err)
	}
	t.ID, err = NewTenantID(id)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// SetStatus updates the tenant's status.
func (Tenants) SetStatus(ctx context.Context, c *Conn, status TenantStatus) error {
	const q = `UPDATE tenants SET status = $2 WHERE tenant_id = $1`

	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), string(status))
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
