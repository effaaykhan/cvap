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

	"github.com/effaaykhan/cvap/internal/hostkeytrust"
	"github.com/effaaykhan/cvap/internal/store"
)

// credential pin / unpin: the operator pin on a credential profile (ADR-091 §4,
// ADR-100). A pinned known_hosts line outranks whatever discovery observed for
// the host it names — the one trust root a person chooses. Like set-domain and
// set-password this runs at a shell, outside the operator API, so it audits
// itself in the same transaction as the change.
func credentialCmd(log *slog.Logger, args []string) error {
	if len(args) < 1 {
		return errors.New("cvap-cli credential: a sub-command is required: pin | unpin")
	}
	switch args[0] {
	case "pin":
		return credentialPin(log, args[1:])
	case "unpin":
		return credentialUnpin(log, args[1:])
	default:
		return fmt.Errorf("cvap-cli credential: unknown sub-command %q", args[0])
	}
}

// profileFlags is what both verbs need: the tenant, the profile, and a reason.
func profileFlags(fs *flag.FlagSet) (tenant, profile, reason *string) {
	tenant = fs.String("tenant", "", "tenant id (required; from bootstrap output)")
	profile = fs.String("profile", "", "credential profile name or id (required)")
	reason = fs.String("reason", "", "why, recorded in the audit log (required)")
	return
}

func openForProfile(ctx context.Context, tenantStr string) (*store.DB, store.TenantID, error) {
	tenantUUID, err := uuid.Parse(tenantStr)
	if err != nil {
		return nil, store.TenantID{}, fmt.Errorf("--tenant is not a uuid: %w", err)
	}
	tenantID, err := store.NewTenantID(tenantUUID)
	if err != nil {
		return nil, store.TenantID{}, err
	}
	dbURL := os.Getenv("APP_DATABASE_URL")
	if dbURL == "" {
		return nil, store.TenantID{}, errors.New("APP_DATABASE_URL is not set (the same value cvap-core uses)")
	}
	db, err := store.Open(ctx, store.Config{URL: dbURL})
	if err != nil {
		return nil, store.TenantID{}, fmt.Errorf("database: %w", err)
	}
	return db, tenantID, nil
}

func resolveProfile(ctx context.Context, c *store.Conn, ref string) (*store.CredentialProfileSummary, error) {
	if id, err := uuid.Parse(ref); err == nil {
		all, err := (store.CredentialProfiles{}).List(ctx, c)
		if err != nil {
			return nil, err
		}
		for i := range all {
			if all[i].ID == id {
				return &all[i], nil
			}
		}
		return nil, fmt.Errorf("no credential profile %s in that tenant", ref)
	}
	p, err := (store.CredentialProfiles{}).GetByName(ctx, c, ref)
	if err != nil {
		return nil, fmt.Errorf("no credential profile named %q in that tenant: %w", ref, err)
	}
	return p, nil
}

func credentialPin(log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("credential pin", flag.ContinueOnError)
	tenantStr, profile, reason := profileFlags(fs)
	file := fs.String("known-hosts", "", "path to a known_hosts file: plain 'host keytype base64' lines (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tenantStr == "" || *profile == "" || *reason == "" || *file == "" {
		return errors.New("cvap-cli credential pin: --tenant, --profile, --reason and --known-hosts are all required")
	}
	raw, err := os.ReadFile(*file)
	if err != nil {
		return fmt.Errorf("cvap-cli credential pin: %w", err)
	}
	material, fps, err := hostkeytrust.ValidatePin(string(raw))
	if err != nil {
		return fmt.Errorf("cvap-cli credential pin: %w", err)
	}
	ctx := context.Background()
	db, tenantID, err := openForProfile(ctx, *tenantStr)
	if err != nil {
		return fmt.Errorf("cvap-cli credential pin: %w", err)
	}
	defer db.Close()
	now := time.Now().UTC()
	var pid uuid.UUID
	err = db.Write(ctx, tenantID, func(ctx context.Context, c *store.Conn) error {
		p, err := resolveProfile(ctx, c, *profile)
		if err != nil {
			return err
		}
		pid = p.ID
		if err := (store.CredentialProfiles{}).SetKnownHosts(ctx, c, p.ID, material, now); err != nil {
			return err
		}
		return (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
			ActorID: nil, ActorType: store.ActorUser, // changed at a shell, not by a logged-in user
			Action: "credential.pinned", ResourceType: "credential_profile", ResourceID: &pid,
			Detail: map[string]any{"reason": *reason, "lines": len(fps), "fingerprints": fps, "via": "cvap-cli",
				"note": "an operator pin outranks the observed key for every host it names (ADR-091 §4); this is a trust decision, not a verification"},
		})
	})
	if err != nil {
		return fmt.Errorf("cvap-cli credential pin: %w", err)
	}
	log.Info("host keys pinned on the credential profile",
		slog.String("tenant_id", tenantID.String()), slog.String("profile_id", pid.String()),
		slog.Int("lines", len(fps)), slog.Any("fingerprints", fps))
	return nil
}

func credentialUnpin(log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("credential unpin", flag.ContinueOnError)
	tenantStr, profile, reason := profileFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *tenantStr == "" || *profile == "" || *reason == "" {
		return errors.New("cvap-cli credential unpin: --tenant, --profile and --reason are all required")
	}
	ctx := context.Background()
	db, tenantID, err := openForProfile(ctx, *tenantStr)
	if err != nil {
		return fmt.Errorf("cvap-cli credential unpin: %w", err)
	}
	defer db.Close()
	now := time.Now().UTC()
	var pid uuid.UUID
	var had int
	err = db.Write(ctx, tenantID, func(ctx context.Context, c *store.Conn) error {
		p, err := resolveProfile(ctx, c, *profile)
		if err != nil {
			return err
		}
		pid, had = p.ID, p.PinLines
		if had == 0 {
			return errors.New("that profile carries no pin to clear")
		}
		if err := (store.CredentialProfiles{}).SetKnownHosts(ctx, c, p.ID, "", now); err != nil {
			return err
		}
		return (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
			ActorID: nil, ActorType: store.ActorUser,
			Action: "credential.pin_cleared", ResourceType: "credential_profile", ResourceID: &pid,
			Detail: map[string]any{"reason": *reason, "lines_cleared": had, "via": "cvap-cli",
				"note": "the fleet path uses the observed key for this profile's targets again (two sightings at the address, ADR-094)"},
		})
	})
	if err != nil {
		return fmt.Errorf("cvap-cli credential unpin: %w", err)
	}
	log.Info("pin cleared from the credential profile",
		slog.String("tenant_id", tenantID.String()), slog.String("profile_id", pid.String()), slog.Int("lines_cleared", had))
	return nil
}
