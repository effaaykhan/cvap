package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/control/credential"
	"github.com/effaaykhan/cvap/internal/store"
)

// tenant dispatches the tenant sub-commands: set-domain and set-password.
func tenant(log *slog.Logger, args []string) error {
	if len(args) == 0 {
		return errors.New("cvap-cli tenant: a sub-command is required (set-domain, set-password)")
	}
	switch args[0] {
	case "set-domain":
		return tenantSetDomain(log, args[1:])
	case "set-password":
		return tenantSetPassword(log, args[1:])
	default:
		return fmt.Errorf("cvap-cli tenant: unknown sub-command %q", args[0])
	}
}

// tenantSetDomain changes the host a tenant authenticates at.
//
// Login resolves the tenant from the request Host (ADR-041), so a deployment
// whose domain is not the host operators actually use cannot be logged into —
// the failure is a 401 at first login, not an error at install. This is the
// supported way to correct that after the fact (an IP that changed, a domain
// typed wrong) without reaching into the database by hand.
//
// It is a privileged operation: it changes which request authenticates as the
// tenant. It happens outside the operator API, where scan.* and enrollment are
// audited, so it audits itself in the same transaction as the change — the same
// rule bootstrap and enroll-token follow.
func tenantSetDomain(log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("tenant set-domain", flag.ContinueOnError)
	tenantStr := fs.String("tenant", "", "tenant id whose domain to change (required; from bootstrap output)")
	domainFlag := fs.String("domain", "", "the host operators reach this deployment at (required; an IP or DNS name)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tenantStr == "" || *domainFlag == "" {
		return errors.New("cvap-cli tenant set-domain: --tenant and --domain are both required")
	}
	tenantUUID, err := uuid.Parse(*tenantStr)
	if err != nil {
		return fmt.Errorf("cvap-cli tenant set-domain: --tenant is not a uuid: %w", err)
	}
	tenantID, err := store.NewTenantID(tenantUUID)
	if err != nil {
		return err
	}
	// The canonical form the store will write, computed here so the audit event
	// and the log record the value that actually took effect, not the raw input.
	newDomain := strings.ToLower(strings.TrimSpace(*domainFlag))

	dbURL := os.Getenv("APP_DATABASE_URL")
	if dbURL == "" {
		return errors.New("cvap-cli tenant set-domain: APP_DATABASE_URL is not set (the same value cvap-core uses)")
	}
	ctx := context.Background()
	db, err := store.Open(ctx, store.Config{URL: dbURL})
	if err != nil {
		return fmt.Errorf("cvap-cli tenant set-domain: database: %w", err)
	}
	defer db.Close()

	var oldDomain string
	err = db.Write(ctx, tenantID, func(ctx context.Context, c *store.Conn) error {
		cur, err := (store.Tenants{}).Get(ctx, c)
		if err != nil {
			return fmt.Errorf("no tenant with that id: %w", err)
		}
		oldDomain = cur.Domain
		if err := (store.Tenants{}).SetDomain(ctx, c, newDomain); err != nil {
			return err
		}
		id := tenantID.UUID()
		return (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
			ActorID:      nil, // changed at a shell, not by a logged-in user
			ActorType:    store.ActorUser,
			Action:       "tenant.domain_changed",
			ResourceType: "tenant",
			ResourceID:   &id,
			Detail:       map[string]any{"old_domain": oldDomain, "new_domain": newDomain},
		})
	})
	if err != nil {
		return fmt.Errorf("cvap-cli tenant set-domain: %w", err)
	}

	log.Info("tenant domain changed",
		slog.String("tenant_id", tenantID.String()),
		slog.String("old_domain", oldDomain),
		slog.String("new_domain", newDomain))
	log.Warn("operators sign in ONLY at the new host — the tenant resolves from the request Host (ADR-041)",
		slog.String("domain", newDomain))
	return nil
}

// tenantSetPassword replaces an operator's password with a generated
// first-login one, the way bootstrap issued the first.
//
// A password is stored only as an argon2id verifier, so a lost one is not
// recoverable, and until this existed the only remedies were a second bootstrap
// (refused for a live tenant) or reaching into the database by hand. This is the
// supported path: the same generator and encoder as bootstrap, `must_change`
// set so the printed value is a first-login credential and not a durable one,
// the lockout counter cleared with it (the store's Set does that), and the
// change audited in the same transaction — a privileged operation outside the
// operator API audits itself, the rule bootstrap, enroll-token and set-domain
// follow. It ends the way bootstrap does: by verifying the new credential through
// the login path at the tenant's domain, and refusing to report success otherwise.
func tenantSetPassword(log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("tenant set-password", flag.ContinueOnError)
	tenantStr := fs.String("tenant", "", "tenant id the user belongs to (required; from bootstrap output)")
	email := fs.String("email", "", "the operator's login email (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tenantStr == "" || *email == "" {
		return errors.New("cvap-cli tenant set-password: --tenant and --email are both required")
	}
	tenantUUID, err := uuid.Parse(*tenantStr)
	if err != nil {
		return fmt.Errorf("cvap-cli tenant set-password: --tenant is not a uuid: %w", err)
	}
	tenantID, err := store.NewTenantID(tenantUUID)
	if err != nil {
		return err
	}
	dbURL := os.Getenv("APP_DATABASE_URL")
	if dbURL == "" {
		return errors.New("cvap-cli tenant set-password: APP_DATABASE_URL is not set (the same value cvap-core uses)")
	}

	password, err := generatePassword()
	if err != nil {
		return err
	}
	phc, err := credential.Hash(password)
	if err != nil {
		return fmt.Errorf("cvap-cli tenant set-password: hash password: %w", err)
	}

	ctx := context.Background()
	db, err := store.Open(ctx, store.Config{URL: dbURL})
	if err != nil {
		return fmt.Errorf("cvap-cli tenant set-password: database: %w", err)
	}
	defer db.Close()

	var domain string
	var userID uuid.UUID
	err = db.Write(ctx, tenantID, func(ctx context.Context, c *store.Conn) error {
		cur, err := (store.Tenants{}).Get(ctx, c)
		if err != nil {
			return fmt.Errorf("no tenant with that id: %w", err)
		}
		domain = cur.Domain
		u, err := (store.Users{}).GetByEmail(ctx, c, *email)
		if err != nil {
			return fmt.Errorf("no user %q in that tenant: %w", *email, err)
		}
		userID = u.ID
		if err := (store.Credentials{}).Set(ctx, c, u.ID, phc, true); err != nil {
			return fmt.Errorf("set credential: %w", err)
		}
		return (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
			ActorID:      nil, // changed at a shell, not by a logged-in user
			ActorType:    store.ActorUser,
			Action:       "user.password_reset",
			ResourceType: "user",
			ResourceID:   &userID,
			Detail:       map[string]any{"email": *email, "must_change": true, "via": "cvap-cli"},
		})
	})
	if err != nil {
		return fmt.Errorf("cvap-cli tenant set-password: %w", err)
	}
	if err := verifyBootstrapLogin(ctx, db, domain, *email, password); err != nil {
		return fmt.Errorf("cvap-cli tenant set-password: the new credential does not verify: %w", err)
	}

	log.Info("operator password reset",
		slog.String("tenant_id", tenantID.String()),
		slog.String("user_id", userID.String()),
		slog.String("email", *email),
		slog.String("domain", domain))
	emitSecret("new password (must be changed on first login): ", password)
	return nil
}
