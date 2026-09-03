package store

// An in-package test, unlike everything else in this directory, because
// resolveTenant is unexported and must stay that way (ADR-031).
//
// It is not here to satisfy the unused linter. resolveTenant has no production
// caller yet — enrolment is a later session — and the honest options were a
// //nolint:unused with a promise, or a test that actually runs it. The second
// covers the Go wrapper around the SECURITY DEFINER function, which the external
// test package cannot reach, so the properties below are checked rather than
// asserted in a comment:
//
//   - it resolves with NO tenant context, which is the whole reason it exists;
//   - a revoked scan point does not resolve;
//   - an unknown fingerprint and a revoked one fail IDENTICALLY, so the Go layer
//     does not reintroduce the enrolment oracle the SQL layer avoids by
//     returning NULL rather than raising.

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func resolveTestDB(t *testing.T) *DB {
	t.Helper()
	url := os.Getenv("CVAP_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CVAP_TEST_DATABASE_URL not set; skipping resolveTenant tests")
	}
	db, err := Open(context.Background(), Config{URL: url})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func TestResolveTenant(t *testing.T) {
	db := resolveTestDB(t)
	ctx := context.Background()

	tenant, err := NewTenantID(uuid.New())
	if err != nil {
		t.Fatal(err)
	}

	okFP := "resolve-ok-" + uuid.NewString()
	revokedFP := "resolve-revoked-" + uuid.NewString()

	if err := db.Write(ctx, tenant, func(ctx context.Context, c *Conn) error {
		if _, err := (Tenants{}).Create(ctx, c, "resolve-"+uuid.NewString()[:8],
			"res"+strings.ReplaceAll(uuid.NewString(), "-", "")[:20]+".test", DeploymentOnPrem); err != nil {
			return err
		}
		z, err := (Zones{}).Create(ctx, c, "resolve-zone", ZoneInternal, 1, "")
		if err != nil {
			return err
		}
		if _, err := (ScanPoints{}).Create(ctx, c, z.ID, "ok", "1", "v1", okFP); err != nil {
			return err
		}
		sp, err := (ScanPoints{}).Create(ctx, c, z.ID, "revoked", "1", "v1", revokedFP)
		if err != nil {
			return err
		}
		return (ScanPoints{}).SetStatus(ctx, c, sp.ID, ScanPointRevoked)
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Resolves with no tenant context at all — the point of the function.
	got, err := db.resolveTenant(ctx, okFP)
	if err != nil {
		t.Fatalf("resolveTenant on an enrollable fingerprint: %v", err)
	}
	if got != tenant {
		t.Errorf("resolved to %s, want %s", got, tenant)
	}

	// The three failure cases must be indistinguishable to the caller. If any
	// of them returned a different error, the caller could tell an enrolled
	// fingerprint from an unenrolled one, which is the oracle ADR-031 closes.
	for _, tc := range []struct {
		name        string
		fingerprint string
	}{
		{"revoked scan point", revokedFP},
		{"unknown fingerprint", "resolve-nope-" + uuid.NewString()},
		{"empty fingerprint", ""},
	} {
		_, err := db.resolveTenant(ctx, tc.fingerprint)
		if !errors.Is(err, ErrTenantNotResolved) {
			t.Errorf("%s: got %v, want ErrTenantNotResolved — differing errors here "+
				"are an oracle for whether a fingerprint is enrolled", tc.name, err)
		}
	}
}

// resolveTenant must not return a usable TenantID on failure. A zero TenantID
// reaching Read or Write is rejected there too, but two layers is right for the
// one function that runs without a tenant.
func TestResolveTenantReturnsNoUsableTenantOnFailure(t *testing.T) {
	db := resolveTestDB(t)

	got, err := db.resolveTenant(context.Background(), "resolve-absent-"+uuid.NewString())
	if err == nil {
		t.Fatal("an unknown fingerprint resolved")
	}
	if !got.IsZero() {
		t.Errorf("returned a non-zero TenantID %s alongside an error", got)
	}
	if err := db.Read(context.Background(), got, func(context.Context, *Conn) error {
		t.Error("Read accepted the TenantID from a failed resolve")
		return nil
	}); !errors.Is(err, ErrNoTenantContext) {
		t.Errorf("Read with a failed resolve's TenantID: got %v, want ErrNoTenantContext", err)
	}
}
