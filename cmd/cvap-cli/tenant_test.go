package main

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/control/credential"
	"github.com/effaaykhan/cvap/internal/store"
)

// mutate:subject cmd/cvap-cli/bootstrap.go
// mutate:test    ./cmd/cvap-cli/ -run TestBootstrapRequiresDomain|TestTenantSetDomainChangesAndAudits|TestTenantSetPasswordResetsAndAudits
//
// mutate:case    bootstrap accepts a missing --domain (the localhost-default bug)
// mutate:old     if *domain == "" {
// mutate:new     if *domain == "\x00" {
//
// mutate:subject cmd/cvap-cli/tenant.go
//
// mutate:case    the privileged domain change is not audited
// mutate:old     Action:       "tenant.domain_changed",
// mutate:new     Action:       "tenant.silently_changed",
//
// mutate:case    a reset password is issued as a durable credential, not a first-login one
// mutate:old     if err := (store.Credentials{}).Set(ctx, c, u.ID, phc, true); err != nil {
// mutate:new     if err := (store.Credentials{}).Set(ctx, c, u.ID, phc, false); err != nil {
//
// mutate:case    the password reset is not audited
// mutate:old     Action:       "user.password_reset",
// mutate:new     Action:       "user.silently_reset",
//
// The first mutation restores the default that produced the login bug — a
// bootstrap that accepts no domain and guesses; TestBootstrapRequiresDomain
// kills it. The second stops the domain change naming itself in the audit log;
// TestTenantSetDomainChangesAndAudits reads the row back and kills it.

// TestBootstrapRequiresDomain: --domain has no default, so an operator on a box
// reached by IP is forced to say so at install time rather than meeting a 401 at
// first login. Fails before any DB work, so no database is needed.
func TestBootstrapRequiresDomain(t *testing.T) {
	err := bootstrap(discardLog(), []string{"--admin-email", "a@b.test"})
	if err == nil || !strings.Contains(err.Error(), "--domain is required") {
		t.Fatalf("bootstrap without --domain must require it, got: %v", err)
	}
}

// TestTenantSetDomainChangesAndAudits drives the set-domain command end to end:
// the domain is updated, and the change writes an audit event naming the old and
// new host — the privileged-operation-outside-the-API audit the rest of the CLI
// has.
func TestTenantSetDomainChangesAndAudits(t *testing.T) {
	db := bootstrapTestDB(t) // skips without CVAP_TEST_DATABASE_URL
	ctx := context.Background()
	if os.Getenv("APP_DATABASE_URL") == "" {
		t.Setenv("APP_DATABASE_URL", os.Getenv("CVAP_TEST_DATABASE_URL"))
	}

	tenant, err := store.NewTenantID(uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	d1 := "old" + strings.ReplaceAll(uuid.NewString(), "-", "")[:18] + ".test"
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := (store.Tenants{}).Create(ctx, c, "sd", d1, store.DeploymentOnPrem)
		return err
	}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	d2 := "new" + strings.ReplaceAll(uuid.NewString(), "-", "")[:18] + ".test"
	if err := tenantSetDomain(discardLog(), []string{"--tenant", tenant.String(), "--domain", d2}); err != nil {
		t.Fatalf("set-domain: %v", err)
	}

	var gotDomain, action, oldD, newD string
	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		if err := c.QueryRow(ctx, `SELECT domain FROM tenants WHERE tenant_id = $1`, tenant.UUID()).Scan(&gotDomain); err != nil {
			return err
		}
		// RLS scopes audit_events to this fresh tenant; its only event is the change.
		return c.QueryRow(ctx, `SELECT action, detail->>'old_domain', detail->>'new_domain'
			FROM audit_events ORDER BY occurred_at DESC LIMIT 1`).Scan(&action, &oldD, &newD)
	}); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if gotDomain != d2 {
		t.Errorf("domain = %q, want %q", gotDomain, d2)
	}
	if action != "tenant.domain_changed" || oldD != d1 || newD != d2 {
		t.Errorf("audit event: action=%q old=%q new=%q; want tenant.domain_changed %q -> %q",
			action, oldD, newD, d1, d2)
	}
}

// TestTenantSetPasswordResetsAndAudits drives set-password end to end against a
// locked-out account with a known old password: afterwards the old password no
// longer verifies, the stored hash is a fresh first-login credential (must_change
// set), the lockout is cleared, and the reset names itself in the audit log. The
// new password is printed, not returned, so the test reads what changed rather
// than what was said.
func TestTenantSetPasswordResetsAndAudits(t *testing.T) {
	db := bootstrapTestDB(t) // skips without CVAP_TEST_DATABASE_URL
	ctx := context.Background()
	if os.Getenv("APP_DATABASE_URL") == "" {
		t.Setenv("APP_DATABASE_URL", os.Getenv("CVAP_TEST_DATABASE_URL"))
	}
	tenant, err := store.NewTenantID(uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	domain := "pw" + strings.ReplaceAll(uuid.NewString(), "-", "")[:18] + ".test"
	const email = "op@example.test"
	const oldPassword = "the-old-password-that-was-lost"
	oldPHC, err := credential.Hash(oldPassword)
	if err != nil {
		t.Fatal(err)
	}
	var userID uuid.UUID
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		if _, err := (store.Tenants{}).Create(ctx, c, "pw", domain, store.DeploymentOnPrem); err != nil {
			return err
		}
		role, err := (store.Roles{}).Create(ctx, c, "operator", []byte(`{}`))
		if err != nil {
			return err
		}
		u, err := (store.Users{}).Create(ctx, c, role.ID, email, string(store.AuthLocal))
		if err != nil {
			return err
		}
		userID = u.ID
		if err := (store.Credentials{}).Set(ctx, c, u.ID, oldPHC, false); err != nil {
			return err
		}
		// Locked out: the reset must clear this, or the operator who lost the
		// password and then guessed at it stays locked with the new one.
		for i := 0; i < store.LockoutThreshold; i++ {
			if err := (store.Credentials{}).RecordFailure(ctx, c, u.ID); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := tenantSetPassword(discardLog(), []string{"--tenant", tenant.String(), "--email", email}); err != nil {
		t.Fatalf("set-password: %v", err)
	}

	var hash, action, viaDetail string
	var mustChange bool
	var failed int
	var lockedUntil *string
	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		if err := c.QueryRow(ctx, `SELECT password_hash, must_change, failed_attempts, locked_until::text
			FROM user_credentials WHERE user_id = $1`, userID).Scan(&hash, &mustChange, &failed, &lockedUntil); err != nil {
			return err
		}
		return c.QueryRow(ctx, `SELECT action, detail->>'via' FROM audit_events
			WHERE resource_id = $1 ORDER BY occurred_at DESC LIMIT 1`, userID).Scan(&action, &viaDetail)
	}); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if ok, _, _ := credential.Verify(hash, oldPassword); ok {
		t.Error("the old password still verifies after the reset")
	}
	if !mustChange {
		t.Error("must_change is false: the printed password was issued as a durable credential")
	}
	if failed != 0 || lockedUntil != nil {
		t.Errorf("lockout not cleared: failed_attempts=%d locked_until=%v", failed, lockedUntil)
	}
	if action != "user.password_reset" || viaDetail != "cvap-cli" {
		t.Errorf("audit event: action=%q via=%q; want user.password_reset via cvap-cli", action, viaDetail)
	}
}
