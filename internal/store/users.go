package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type UserStatus string

const (
	UserInvited  UserStatus = "invited"
	UserActive   UserStatus = "active"
	UserDisabled UserStatus = "disabled"
)

type Role struct {
	ID          uuid.UUID
	Name        string
	Permissions []byte // jsonb
	CreatedAt   time.Time
}

type User struct {
	ID       uuid.UUID
	RoleID   uuid.UUID
	Email    string
	Provider string
	Status   UserStatus
	Created  time.Time
}

type Users struct{}
type Roles struct{}

func (Roles) Create(ctx context.Context, c *Conn, name string, permissions []byte) (*Role, error) {
	if permissions == nil {
		permissions = []byte(`{}`)
	}
	const q = `
		INSERT INTO roles (tenant_id, name, permissions)
		VALUES ($1, $2, $3)
		RETURNING role_id, name, permissions, created_at`

	var r Role
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), name, permissions).
		Scan(&r.ID, &r.Name, &r.Permissions, &r.CreatedAt)
	if err != nil {
		return nil, mapError(err)
	}
	return &r, nil
}

func (Roles) List(ctx context.Context, c *Conn) ([]Role, error) {
	const q = `
		SELECT role_id, name, permissions, created_at
		  FROM roles
		 WHERE tenant_id = $1
		 ORDER BY name`

	rows, err := c.Query(ctx, q, c.Tenant().UUID())
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []Role
	for rows.Next() {
		var r Role
		if err := rows.Scan(&r.ID, &r.Name, &r.Permissions, &r.CreatedAt); err != nil {
			return nil, mapError(err)
		}
		out = append(out, r)
	}
	return out, mapError(rows.Err())
}

// Create inserts a user.
//
// email is stored exactly as given. Do NOT normalise it on write: the unique
// index is on (tenant_id, lower(email)), which is what makes Alice@corp.com and
// alice@corp.com the same account, and lowercasing on write would additionally
// lose what the user typed — which then shows up in outbound mail.
//
// That index is also per-tenant rather than global, so the same person may hold
// accounts at two tenants. The consequence, which belongs to whoever writes
// login rather than here: there is no lookup path from a bare email to an
// account. Tenant is resolved first, by subdomain, SSO issuer or explicit
// selection. See internal/control/CLAUDE.md.
func (Users) Create(ctx context.Context, c *Conn, roleID uuid.UUID, email, provider string) (*User, error) {
	const q = `
		INSERT INTO users (tenant_id, role_id, email, auth_provider)
		VALUES ($1, $2, $3, $4)
		RETURNING user_id, role_id, email, auth_provider, status, created_at`

	var u User
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), roleID, email, provider).
		Scan(&u.ID, &u.RoleID, &u.Email, &u.Provider, &u.Status, &u.Created)
	if err != nil {
		return nil, mapError(err)
	}
	return &u, nil
}

func (Users) GetByID(ctx context.Context, c *Conn, id uuid.UUID) (*User, error) {
	const q = `
		SELECT user_id, role_id, email, auth_provider, status, created_at
		  FROM users
		 WHERE tenant_id = $1 AND user_id = $2`

	var u User
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), id).
		Scan(&u.ID, &u.RoleID, &u.Email, &u.Provider, &u.Status, &u.Created)
	if err != nil {
		return nil, mapError(err)
	}
	return &u, nil
}

// GetByEmail looks a user up WITHIN the connection's tenant.
//
// Compared lowercased, matching the functional unique index. There is
// deliberately no cross-tenant variant of this method — see Create.
func (Users) GetByEmail(ctx context.Context, c *Conn, email string) (*User, error) {
	const q = `
		SELECT user_id, role_id, email, auth_provider, status, created_at
		  FROM users
		 WHERE tenant_id = $1 AND lower(email) = lower($2)`

	var u User
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), email).
		Scan(&u.ID, &u.RoleID, &u.Email, &u.Provider, &u.Status, &u.Created)
	if err != nil {
		return nil, mapError(err)
	}
	return &u, nil
}

func (Users) List(ctx context.Context, c *Conn) ([]User, error) {
	const q = `
		SELECT user_id, role_id, email, auth_provider, status, created_at
		  FROM users
		 WHERE tenant_id = $1
		 ORDER BY lower(email)`

	rows, err := c.Query(ctx, q, c.Tenant().UUID())
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.RoleID, &u.Email, &u.Provider, &u.Status, &u.Created); err != nil {
			return nil, mapError(err)
		}
		out = append(out, u)
	}
	return out, mapError(rows.Err())
}

func (Users) SetStatus(ctx context.Context, c *Conn, id uuid.UUID, status UserStatus) error {
	const q = `UPDATE users SET status = $3 WHERE tenant_id = $1 AND user_id = $2`

	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), id, string(status))
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
