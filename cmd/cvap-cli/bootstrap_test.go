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
// mutate:test    ./cmd/cvap-cli/ -run TestBootstrapSelfVerify
//
// mutate:case    the self-verify ignores whether the credential authenticates
// mutate:old     if !ok {
// mutate:new     if ok {
//
// Inverting the check makes verifyBootstrapLogin accept a WRONG password and
// reject the correct one; the two cases below kill it. This is the check that
// makes "a bootstrap that cannot log in has not bootstrapped" true — the login
// failure this session chased hid behind a silent 401, and a bootstrap that
// exercises its own login path is what turns that into a loud failure at
// creation instead.

func bootstrapTestDB(t *testing.T) *store.DB {
	t.Helper()
	url := os.Getenv("CVAP_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CVAP_TEST_DATABASE_URL not set; skipping DB-backed bootstrap test")
	}
	db, err := store.Open(context.Background(), store.Config{URL: url})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

// TestBootstrapSelfVerify drives verifyBootstrapLogin — the login path bootstrap
// now runs against what it wrote — through the three ways an install is broken:
// a correct credential (must pass), a wrong password (must be refused), and a
// domain that resolves to no tenant (must be refused, because login reads Host).
func TestBootstrapSelfVerify(t *testing.T) {
	db := bootstrapTestDB(t)
	ctx := context.Background()

	// A per-test domain so the suite is concurrency-safe against one database.
	domain := "sv" + strings.ReplaceAll(uuid.NewString(), "-", "")[:20] + ".test"
	const email = "admin"
	const password = "correct horse battery staple"

	tenant, err := store.NewTenantID(uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	phc, err := credential.Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		if _, err := (store.Tenants{}).Create(ctx, c, "sv", domain, store.DeploymentOnPrem); err != nil {
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
		if err := (store.Users{}).SetStatus(ctx, c, u.ID, store.UserActive); err != nil {
			return err
		}
		return (store.Credentials{}).Set(ctx, c, u.ID, phc, true)
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// The password bootstrap "printed" authenticates through the whole path.
	if err := verifyBootstrapLogin(ctx, db, domain, email, password); err != nil {
		t.Errorf("correct password should verify, got: %v", err)
	}
	// A wrong password must fail — the load-bearing check.
	if err := verifyBootstrapLogin(ctx, db, domain, email, "not the password"); err == nil {
		t.Error("a wrong password must fail the self-verify, but it passed")
	}
	// A domain that resolves to no tenant must fail — the failure mode this whole
	// session was: a tenant nobody can reach by the host they use.
	if err := verifyBootstrapLogin(ctx, db, "no-such-"+domain, email, password); err == nil {
		t.Error("an unresolvable domain must fail the self-verify, but it passed")
	}
}
