package main

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/store"
)

// mutate:subject cmd/cvap-cli/bootstrap.go
// mutate:test    ./cmd/cvap-cli/ -run TestBootstrapRequiresDomain|TestTenantSetDomainChangesAndAudits
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
