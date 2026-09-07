package store

import (
	"context"
	"fmt"
	"strings"
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

	// Domain is the hostname this tenant is reached at, lowercased.
	//
	// Resolved to a tenant by tenant_for_domain() before any handler runs
	// (ADR-041). Every deployment has one, on-prem included, where it is
	// typically localhost.
	Domain    string
	CreatedAt time.Time
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
// The domain is REQUIRED, and there is no overload that omits it.
//
// ADR-041: a login request carries a hostname, a form and nothing else, so the
// hostname is the only thing that can name a tenant before authentication. A
// tenant created without one is a tenant nobody can sign in to — and a nullable
// column with a "set it later" convention would make that a runtime surprise
// rather than a compile error. On-prem sets one too, usually localhost; the
// single-tenant path that skips this is the branch ADR-017 exists to prevent.
//
// Lowercased here as well as in SQL, because a caller with a mixed-case hostname
// would otherwise write a row that tenant_for_domain can never match.
func (Tenants) Create(ctx context.Context, c *Conn, name, domain string, mode DeploymentMode) (*Tenant, error) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil, fmt.Errorf("store: a tenant needs a domain (ADR-041); on-prem deployments use localhost")
	}

	const q = `
		INSERT INTO tenants (tenant_id, name, domain, deployment_mode)
		VALUES ($1, $2, $3, $4)
		RETURNING tenant_id, name, domain, deployment_mode, status, created_at`

	var t Tenant
	var id uuid.UUID
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), name, domain, string(mode)).
		Scan(&id, &t.Name, &t.Domain, &t.DeploymentMode, &t.Status, &t.CreatedAt)
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
		SELECT tenant_id, name, domain, deployment_mode, status, created_at
		  FROM tenants
		 WHERE tenant_id = $1`

	var t Tenant
	var id uuid.UUID
	err := c.QueryRow(ctx, q, c.Tenant().UUID()).
		Scan(&id, &t.Name, &t.Domain, &t.DeploymentMode, &t.Status, &t.CreatedAt)
	if err != nil {
		return nil, mapError(err)
	}
	t.ID, err = NewTenantID(id)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// SetDomain changes the host a tenant is reached at — the Host that resolves to
// it before authentication (ADR-041). Lowercased and required, exactly as Create
// treats it, because tenant_for_domain matches the stored value and a mixed-case
// or empty domain is one nobody can sign in to. A domain already used by another
// tenant fails on the unique index (mapped, not swallowed).
//
// This changes which request authenticates as this tenant, so it is a privileged
// operation; its caller (cvap-cli tenant set-domain) records an audit event in
// the same transaction, the way bootstrap and enroll-token do.
func (Tenants) SetDomain(ctx context.Context, c *Conn, domain string) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return fmt.Errorf("store: a tenant needs a domain (ADR-041); on-prem deployments use the host operators reach them at")
	}
	const q = `UPDATE tenants SET domain = $2 WHERE tenant_id = $1`
	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), domain)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
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
