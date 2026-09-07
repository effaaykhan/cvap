package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/control/api"
	"github.com/effaaykhan/cvap/internal/control/credential"
	"github.com/effaaykhan/cvap/internal/store"
)

// bootstrap creates the first tenant, an operator role, an admin user with a
// generated password, a local-auth config and a default zone — the minimum for a
// fresh single-node deployment to be logged into and to issue an enrollment
// token.
//
// It writes directly to the database as the application role (APP_DATABASE_URL),
// not through the operator API, because there is no API to reach before this
// runs: the operator API authenticates a session, and there is no user to
// authenticate yet. This is the one operator action that legitimately predates
// authentication, which is why it is a CLI command run on the Core host rather
// than an endpoint. Everything after it — more users, more zones, scans — goes
// through the authenticated API (the full management surface is deferred,
// execution-plan §6.5).
//
// It is NOT idempotent by design: it refuses if the domain already resolves to a
// tenant, rather than editing one, because a second bootstrap of a live
// deployment is a mistake, not a convenience.
func bootstrap(log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	adminEmail := fs.String("admin-email", "", "email of the first admin user (required)")
	tenantName := fs.String("tenant-name", "cvap", "display name for the tenant")
	// No default, deliberately. Login resolves the tenant from the request Host
	// (ADR-041), so the domain must be the host operators will actually reach the
	// deployment at. A `localhost` default is correct only for a loopback install
	// and wrong for every other one — and wrong silently: the tenant is created,
	// bootstrap's own self-check passes against localhost, and the operator meets
	// a 401 at first login with no clue it is a domain mismatch. Forcing the
	// operator to name the host moves that failure to install time with a clear
	// message. (Whichever host they name, set-domain can correct it later.)
	domain := fs.String("domain", "", "REQUIRED: the host operators reach this deployment at (an IP or DNS name); the tenant is resolved from it at login (ADR-041). Use localhost only for a loopback-only install")
	zoneName := fs.String("zone", "internal", "name of the default scan zone")
	zoneType := fs.String("zone-type", string(store.ZoneInternal), "external|dmz|internal|branch|cloud|mgmt")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *adminEmail == "" {
		return errors.New("cvap-cli bootstrap: --admin-email is required")
	}
	if *domain == "" {
		return errors.New("cvap-cli bootstrap: --domain is required — the host operators will reach this deployment at " +
			"(e.g. the server's IP or DNS name; localhost only for a loopback-only install). Login resolves the tenant " +
			"from the request Host, so a deployment whose domain is not the host operators use cannot be signed in to")
	}

	dbURL := os.Getenv("APP_DATABASE_URL")
	if dbURL == "" {
		return errors.New("cvap-cli bootstrap: APP_DATABASE_URL is not set (the same value cvap-core uses)")
	}

	// The operator role gets the whole permission set, taken from the API's
	// closed list rather than a copy kept here: a permission added to the product
	// but not to this list would be one the first admin silently lacked, and the
	// list is the API's to own (permission.go). This is why the CLI depends on
	// the api package — for the authoritative set, not the server.
	perms := map[string]bool{}
	for _, p := range api.PermissionNames() {
		perms[string(p)] = true
	}
	permJSON, err := json.Marshal(perms)
	if err != nil {
		return fmt.Errorf("cvap-cli bootstrap: encode permissions: %w", err)
	}

	password, err := generatePassword()
	if err != nil {
		return err
	}
	phc, err := credential.Hash(password)
	if err != nil {
		return fmt.Errorf("cvap-cli bootstrap: hash password: %w", err)
	}

	ctx := context.Background()
	db, err := store.Open(ctx, store.Config{URL: dbURL})
	if err != nil {
		return fmt.Errorf("cvap-cli bootstrap: database: %w", err)
	}
	defer db.Close()

	// Refuse a second bootstrap. ResolveDomainTenant returns ErrTenantNotResolved
	// for an unknown host, which is the only outcome that means "go ahead"; any
	// other error is a fault and must not be read as permission to proceed.
	if _, err := db.ResolveDomainTenant(ctx, *domain); err == nil {
		return fmt.Errorf("cvap-cli bootstrap: domain %q already resolves to a tenant; this deployment is already bootstrapped", *domain)
	} else if !errors.Is(err, store.ErrTenantNotResolved) {
		return fmt.Errorf("cvap-cli bootstrap: checking for an existing tenant: %w", err)
	}

	// The tenant id is generated here and the whole write runs scoped to it, which
	// is the documented shape for creating a tenant under RLS: the WITH CHECK on
	// `tenants` permits a row whose tenant_id equals the connection's own tenant
	// (internal/store tenants.go). Everything else in the transaction is a child
	// of that tenant and therefore visible to the same scope.
	tenantID, err := store.NewTenantID(uuid.New())
	if err != nil {
		return err
	}

	var (
		zoneID  string
		userID  string
		roleID  string
		tenPrnt string
	)
	err = db.Write(ctx, tenantID, func(ctx context.Context, c *store.Conn) error {
		ten, err := (store.Tenants{}).Create(ctx, c, *tenantName, *domain, store.DeploymentOnPrem)
		if err != nil {
			return fmt.Errorf("create tenant: %w", err)
		}
		tenPrnt = ten.ID.String()

		role, err := (store.Roles{}).Create(ctx, c, "operator", permJSON)
		if err != nil {
			return fmt.Errorf("create role: %w", err)
		}
		roleID = role.ID.String()

		user, err := (store.Users{}).Create(ctx, c, role.ID, *adminEmail, string(store.AuthLocal))
		if err != nil {
			return fmt.Errorf("create user: %w", err)
		}
		userID = user.ID.String()
		// A new user is 'invited'; a session only issues for an 'active' one
		// (store auth.go). Bootstrap's admin is active immediately — there is no
		// invitation flow to complete on a single-node install.
		if err := (store.Users{}).SetStatus(ctx, c, user.ID, store.UserActive); err != nil {
			return fmt.Errorf("activate user: %w", err)
		}
		// must_change = true: the generated password is printed to a terminal and
		// may reach a scrollback or a shell history, so it is a first-login
		// credential, not a durable one.
		if err := (store.Credentials{}).Set(ctx, c, user.ID, phc, true); err != nil {
			return fmt.Errorf("set credential: %w", err)
		}

		// Local auth is the tenant's method. It still does nothing until
		// cvap-core runs with CVAP_CORE_LOCAL_AUTH=1 and the tenant is on-prem
		// (both true here); the flag is Core-wide on purpose, so this row cannot
		// opt a deployment out of an SSO policy on its own (store auth.go).
		if err := (store.AuthConfigs{}).Upsert(ctx, c, store.AuthConfig{Method: store.AuthLocal}, &user.ID); err != nil {
			return fmt.Errorf("set auth config: %w", err)
		}

		zt := store.ZoneType(strings.ToLower(*zoneType))
		zone, err := (store.Zones{}).Create(ctx, c, *zoneName, zt, 0, "created by cvap-cli bootstrap")
		if err != nil {
			return fmt.Errorf("create zone: %w", err)
		}
		zoneID = zone.ID.String()
		return nil
	})
	if err != nil {
		return fmt.Errorf("cvap-cli bootstrap: %w", err)
	}

	// A bootstrap that cannot log in has not bootstrapped. Before printing the
	// password as if it works, exercise the login path against what was just
	// written: the domain must resolve to the tenant (login reads the request
	// Host, ADR-041), the user must exist in it, and the stored credential must
	// verify the generated password with the same encoder login uses. This is the
	// guard that would have turned every failure mode in this session — a domain
	// nobody can reach, a wrote-vs-printed password, an argon2id parameter drift —
	// into a loud bootstrap failure instead of a silent 401 the operator meets
	// later and cannot diagnose.
	if err := verifyBootstrapLogin(ctx, db, *domain, *adminEmail, password); err != nil {
		return fmt.Errorf("cvap-cli bootstrap: the deployment was created but its own login does not work, so it is not usable: %w", err)
	}

	log.Info("bootstrapped a single-node deployment; verified its own login",
		slog.String("tenant_id", tenPrnt),
		slog.String("domain", *domain),
		slog.String("admin_email", *adminEmail),
		slog.String("admin_user_id", userID),
		slog.String("operator_role_id", roleID),
		slog.String("zone_id", zoneID))
	log.Warn("local login requires cvap-core to run with CVAP_CORE_LOCAL_AUTH=1")
	// The domain-binding caveat, stated loudly because it is the defect this
	// session hit: login resolves the tenant from the request Host, so an operator
	// can ONLY sign in at this host. Reaching Core by any other name or IP is a
	// 401 indistinguishable from a wrong password.
	log.Warn("sign in ONLY at the host this domain names — the tenant resolves from the request Host (ADR-041)",
		slog.String("domain", *domain))

	// The password is written straight to stdout, never through a formatting call,
	// for the same reason enrollment tokens are: a credential in a format string
	// is a credential one refactor away from a log line. It is printed once.
	emitSecret("initial admin password (must be changed on first login): ", password)
	return nil
}

// verifyBootstrapLogin runs the login path against what bootstrap just wrote:
// resolve the tenant from the domain (as a request Host would, ADR-041), find the
// user in it, and verify the stored credential against the generated password
// with the same argon2id encoder the login handler uses. An error here means the
// deployment cannot be logged into — which the caller treats as a bootstrap
// failure, not a warning.
func verifyBootstrapLogin(ctx context.Context, db *store.DB, domain, email, password string) error {
	tenant, err := db.ResolveDomainTenant(ctx, domain)
	if err != nil {
		return fmt.Errorf("the domain %q does not resolve to the tenant; no operator could sign in at that host: %w", domain, err)
	}
	var verifyErr error
	readErr := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		u, err := (store.Users{}).GetByEmail(ctx, c, email)
		if err != nil {
			return fmt.Errorf("the admin user %q is not in the tenant the domain resolved to: %w", email, err)
		}
		cred, err := (store.Credentials{}).Get(ctx, c, u.ID)
		if err != nil {
			return fmt.Errorf("the admin credential could not be read: %w", err)
		}
		ok, _, err := credential.Verify(cred.PasswordHash, password)
		if err != nil {
			return fmt.Errorf("the stored credential could not be decoded: %w", err)
		}
		if !ok {
			// The printed password and the stored hash disagree — an encoding
			// transform, a trailing newline, an argon2id parameter drift. Carried
			// out rather than returned so a genuine fault and this integrity
			// failure stay distinguishable, though both fail the bootstrap.
			verifyErr = errors.New("the stored credential does not verify the generated password: the printed password and the stored hash disagree")
		}
		return nil
	})
	if readErr != nil {
		return readErr
	}
	return verifyErr
}

// generatePassword returns a high-entropy first-login password.
//
// 24 bytes from crypto/rand, url-safe base64: ~192 bits, well past anything a
// lockout or an argon2 cost is protecting against, and the point is that it is
// changed on first login anyway.
func generatePassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("cvap-cli bootstrap: generate password: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// emitSecret writes a secret to stdout without any formatting call.
//
// check_secret_logging.py refuses a secret accessor inside fmt/log, which is the
// right rule; the way to honour it is to not use those calls for the secret at
// all, rather than to argue this one is fine.
func emitSecret(label, secret string) {
	_, _ = os.Stdout.WriteString(label)
	_, _ = os.Stdout.WriteString(secret)
	_, _ = os.Stdout.WriteString("\n")
}
