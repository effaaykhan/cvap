package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/control/enrollment"
	"github.com/effaaykhan/cvap/internal/store"
)

// enrollToken issues a single-use, TTL-bounded enrollment token for one zone of
// one tenant, and prints it once.
//
// It wraps enrollment.Issuer, the same code path the operator API uses, so the
// token, its hash storage, its audit event and its expiry are identical to one
// issued through the UI. The tenant and zone are named by id rather than
// resolved from a request host, because there is no request here — this runs on
// the Core host against the database directly. The zone must belong to the
// tenant; Issue refuses it otherwise (ADR-008: a scan point cannot choose its
// own zone, so the operator chooses it here).
func enrollToken(log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("enroll-token", flag.ContinueOnError)
	tenantStr := fs.String("tenant", "", "tenant id the token enrolls into (required; from bootstrap output)")
	zoneStr := fs.String("zone", "", "zone id the enrolled scan point observes from (required; from bootstrap output)")
	ttl := fs.Duration("ttl", enrollment.DefaultTTL, "how long the token is valid; capped at the enrollment maximum")
	description := fs.String("description", "", "a note stored with the token, e.g. which host it is for")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tenantStr == "" || *zoneStr == "" {
		return errors.New("cvap-cli enroll-token: --tenant and --zone are both required")
	}

	tenantUUID, err := uuid.Parse(*tenantStr)
	if err != nil {
		return fmt.Errorf("cvap-cli enroll-token: --tenant is not a uuid: %w", err)
	}
	tenantID, err := store.NewTenantID(tenantUUID)
	if err != nil {
		return err
	}
	zoneID, err := uuid.Parse(*zoneStr)
	if err != nil {
		return fmt.Errorf("cvap-cli enroll-token: --zone is not a uuid: %w", err)
	}

	dbURL := os.Getenv("APP_DATABASE_URL")
	if dbURL == "" {
		return errors.New("cvap-cli enroll-token: APP_DATABASE_URL is not set (the same value cvap-core uses)")
	}

	ctx := context.Background()
	db, err := store.Open(ctx, store.Config{URL: dbURL})
	if err != nil {
		return fmt.Errorf("cvap-cli enroll-token: database: %w", err)
	}
	defer db.Close()

	// issuedBy is nil: the token was minted by an operator at a shell, not by a
	// logged-in user, and the audit event records that honestly rather than
	// attributing it to an account.
	issued, err := enrollment.NewIssuer(db).Issue(ctx, tenantID, zoneID, nil, *ttl, *description)
	if err != nil {
		return fmt.Errorf("cvap-cli enroll-token: %w", err)
	}

	// The token id is deliberately not logged here: the redactor matches "token"
	// as a substring of any attribute key (it cannot tell an id from the secret),
	// so it would print [REDACTED] and read as an error. The id is recorded in
	// the enrollment_token.issue audit event, which is where it belongs.
	log.Info("issued an enrollment token",
		slog.String("zone_id", issued.ZoneID.String()),
		slog.Time("expires_at", issued.ExpiresAt.UTC()),
		slog.Duration("valid_for", time.Until(issued.ExpiresAt).Round(time.Second)))

	// Reveal() at the call site and nowhere else, straight to stdout with no
	// formatting call — the token is a fleet credential and this is its one
	// legitimate rendering (ADR-018, ADR-020). It is not re-derivable: an
	// operator who loses it issues another.
	emitSecret("enrollment token (shown once): ", issued.Token.Reveal())
	return nil
}
