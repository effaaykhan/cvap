package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/effaaykhan/cvap/internal/store"
	"github.com/effaaykhan/cvap/internal/store/storetest"
)

// credential pin / unpin end to end against the database: the pin lands on the
// profile as canonical known_hosts lines, is audited naming the fingerprints,
// and unpin clears it and audits that too (ADR-100).
func TestCredentialPinAndUnpinWriteTheProfileAndAudit(t *testing.T) {
	db := bootstrapTestDB(t)
	ctx := context.Background()
	if os.Getenv("APP_DATABASE_URL") == "" {
		t.Setenv("APP_DATABASE_URL", os.Getenv("CVAP_TEST_DATABASE_URL"))
	}
	tenant, err := store.NewTenantID(uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	storetest.CleanupTenant(t, db, tenant)
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		if _, err := (store.Tenants{}).Create(ctx, c, "pin", "pin"+strings.ReplaceAll(uuid.NewString(), "-", "")[:18]+".test", store.DeploymentOnPrem); err != nil {
			return err
		}
		_, err := c.Exec(ctx, `INSERT INTO credential_profiles (tenant_id, name, cred_type, secret_ref, username) VALUES ($1, 'lab', 'ssh', 'file:///lab.key', 'lab')`, c.Tenant().UUID())
		return err
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := "10.0.0.5 " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	file := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(file, []byte("# pinned by hand\n"+line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := credentialPin(discardLog(), []string{"--tenant", tenant.String(), "--profile", "lab", "--reason", "test", "--known-hosts", file}); err != nil {
		t.Fatalf("pin: %v", err)
	}
	readBack := func() (pin string, actions []string) {
		t.Helper()
		if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
			var p *string
			if err := c.QueryRow(ctx, `SELECT known_hosts FROM credential_profiles WHERE tenant_id = $1 AND name = 'lab'`, c.Tenant().UUID()).Scan(&p); err != nil {
				return err
			}
			if p != nil {
				pin = *p
			}
			r, err := c.Query(ctx, `SELECT action FROM audit_events WHERE tenant_id = $1 AND resource_type = 'credential_profile' ORDER BY occurred_at`, c.Tenant().UUID())
			if err != nil {
				return err
			}
			defer r.Close()
			for r.Next() {
				var a string
				if err := r.Scan(&a); err != nil {
					return err
				}
				actions = append(actions, a)
			}
			return r.Err()
		}); err != nil {
			t.Fatal(err)
		}
		return
	}
	if pin, actions := readBack(); pin != line+"\n" || len(actions) != 1 || actions[0] != "credential.pinned" {
		t.Fatalf("after pin: known_hosts = %q, audit = %v", pin, actions)
	}
	if err := credentialUnpin(discardLog(), []string{"--tenant", tenant.String(), "--profile", "lab", "--reason", "test"}); err != nil {
		t.Fatalf("unpin: %v", err)
	}
	if pin, actions := readBack(); pin != "" || len(actions) != 2 || actions[1] != "credential.pin_cleared" {
		t.Fatalf("after unpin: known_hosts = %q, audit = %v", pin, actions)
	}
	if err := credentialUnpin(discardLog(), []string{"--tenant", tenant.String(), "--profile", "lab", "--reason", "again"}); err == nil {
		t.Error("unpin with no pin: want a refusal")
	}
}
