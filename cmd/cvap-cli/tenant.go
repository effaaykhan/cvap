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

	"github.com/effaaykhan/cvap/internal/store"
)

// tenant dispatches the tenant sub-commands. Today only set-domain.
func tenant(log *slog.Logger, args []string) error {
	if len(args) == 0 {
		return errors.New("cvap-cli tenant: a sub-command is required (set-domain)")
	}
	switch args[0] {
	case "set-domain":
		return tenantSetDomain(log, args[1:])
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
