package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/effaaykhan/cvap/internal/control/credential"
	"github.com/effaaykhan/cvap/internal/store"
)

// Local authentication.
//
// ============================================================================
// On-prem only, by DEPLOYMENT configuration, and the flag is Core-wide.
// ============================================================================
//
// Three conditions, all required, and the order they are checked in does not
// matter because none of them is skippable:
//
//   1. Config.LocalAuthEnabled — set on the DEPLOYMENT, not on a tenant. A
//      per-tenant switch would let the administrator of a tenant enable password
//      login for their own users and opt out of the deployment operator's SSO
//      policy, using a permission granted to them for administering their own
//      tenant.
//   2. tenants.deployment_mode = 'onprem'. ADR-017 makes on-prem a deployment
//      with one tenant row rather than a fork, so this is a property of the row
//      and not of a build.
//   3. tenant_auth_config.method = 'local'. The tenant's own choice, which is
//      necessary and by itself not sufficient.

// LoginRequest is the body of POST /v1/auth/login.
//
// There is no tenant field, and there will not be one. The tenant comes from the
// request host (ADR-041). A tenant a client can name at an unauthenticated
// endpoint is a tenant a client can enumerate.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse is what a successful login returns.
//
// The session token is NOT in the body. It is in an HttpOnly cookie, so that a
// script injected into the operator UI cannot read it. The CSRF token is
// returned here and in a readable cookie, because the page must be able to echo
// it into a header — it carries no authority on its own.
type LoginResponse struct {
	UserID     string    `json:"user_id"`
	Email      string    `json:"email"`
	CSRFToken  string    `json:"csrf_token" doc:"Echo in the X-CVAP-CSRF header on every mutating request."`
	ExpiresAt  time.Time `json:"expires_at"`
	MustChange bool      `json:"must_change_password" doc:"When true, every endpoint except POST /v1/auth/password refuses this session."`
}

// SessionResponse describes the current session to its holder.
type SessionResponse struct {
	UserID      string    `json:"user_id"`
	Email       string    `json:"email"`
	RoleID      string    `json:"role_id"`
	Permissions []string  `json:"permissions" doc:"What this session may do. Empty means nothing: permissions are a permission list, so empty denies (ADR-037)."`
	ExpiresAt   time.Time `json:"expires_at"`
}

// login is deliberately three phases, and the split is the fix for two defects a
// security review demonstrated with probes.
//
// ============================================================================
// The password hash runs OUTSIDE any database transaction.
// ============================================================================
//
// argon2id at 64 MiB and three passes takes tens of milliseconds. Done inside
// db.Write it holds a pooled connection for that whole time — so twenty-odd
// concurrent UNAUTHENTICATED login attempts exhausted the pool and an unrelated
// authenticated read went from 1.8ms to 1.1 SECONDS. That is a denial of
// service against the entire deployment, reachable by anyone who can post to
// /v1/auth/login, and it is caused by the arrangement rather than by the cost of
// the hash.
//
// ============================================================================
// A failed attempt is recorded in a transaction that COMMITS.
// ============================================================================
//
// The first version counted the failure inside the same transaction that then
// returned an error to refuse the login — so the increment was rolled back with
// it, and failed_attempts was still 0 after fifteen wrong passwords. The lockout
// existed in the schema, in the store and in the handler, and engaged never.
//
// The phases:
//
//  1. READ, in one short transaction: the tenant, its auth config, the user and
//     the credential.
//  2. VERIFY, outside any transaction and under a concurrency limit.
//  3. WRITE, in one short transaction: the failure count or the session.
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"The request body could not be read as this endpoint's schema.", err)
		return
	}

	// Login is PUBLIC, so authenticate's unresolved-host branch does not run for
	// it and this handler is where an unconfigured hostname arrives.
	tenant, haveTenant := tenantFrom(r.Context())

	// One refusal for every failure below this point.
	//
	// Unknown address, wrong password, disabled account, locked account, a
	// tenant not configured for local auth, a deployment with the flag off: all
	// of them produce this. The endpoint runs before authentication, so anything
	// it distinguishes is something an unauthenticated caller learns — and "does
	// this address have an account here" is the question users.email's
	// per-tenant uniqueness was designed to refuse (0001,
	// internal/control/CLAUDE.md).
	// It covers an unresolvable HOST as well, which is why the tenant id is
	// logged conditionally rather than being assumed present: a 404 here while a
	// live tenant answers 401 walks the customer list on any deployment with
	// wildcard DNS.
	refuse := func(cause error) {
		attrs := []any{
			"request_id", requestIDFrom(r.Context()),
			"reason", cause.Error(),
		}
		if haveTenant {
			attrs = append(attrs, "tenant_id", tenant.String())
		} else {
			attrs = append(attrs, "host", r.Host)
		}
		s.log.Info("login refused", attrs...)
		writeError(w, r, s.log, http.StatusUnauthorized, CodeUnauthorized,
			"Those credentials are not valid.", nil)
	}

	if !haveTenant {
		// The decoy verification runs even here, so an unconfigured hostname
		// costs the same as a configured one. Without it the 401s are identical
		// and the TIMING is not, which is the same oracle one layer down.
		s.verifyUnderLimit(r.Context(), s.decoyHash, req.Password)
		refuse(errors.New("host resolved to no tenant"))
		return
	}
	if !s.cfg.LocalAuthEnabled {
		refuse(errors.New("local authentication is not enabled on this deployment"))
		return
	}
	if req.Email == "" || req.Password == "" {
		refuse(errors.New("empty email or password"))
		return
	}

	// ---- phase 1: read -----------------------------------------------------

	var (
		user *store.User
		cred *store.Credential
	)
	readErr := s.db.Read(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		t, err := (store.Tenants{}).Get(ctx, c)
		if err != nil {
			return err
		}
		if t.DeploymentMode != store.DeploymentOnPrem {
			return errRefused
		}
		cfg, err := (store.AuthConfigs{}).Get(ctx, c)
		if err != nil {
			return err
		}
		if cfg.Method != store.AuthLocal {
			return errRefused
		}
		user, err = (store.Users{}).GetByEmail(ctx, c, req.Email)
		if err != nil {
			return err
		}
		if user.Status != store.UserActive {
			return errRefused
		}
		cred, err = (store.Credentials{}).Get(ctx, c, user.ID)
		return err
	})
	if readErr != nil && isInfrastructureError(readErr) {
		// A genuine database fault must not present as bad credentials: it would
		// hide an outage behind a message telling operators to check their
		// password.
		writeError(w, r, s.log, http.StatusInternalServerError, CodeInternal,
			"An unexpected error occurred.", readErr)
		return
	}

	// ---- phase 2: verify ---------------------------------------------------

	// The hash runs even when there is no user and no credential, against a
	// fixed decoy verifier.
	//
	// Otherwise an unknown address returns in microseconds and a known one takes
	// fifty milliseconds, which is a user-enumeration oracle that does not care
	// what the response body says. The decoy is the same cost as a real
	// verification because it IS one — of a password nobody has, against a hash
	// generated at startup.
	phc := s.decoyHash
	if cred != nil {
		phc = cred.PasswordHash
	}
	matched, needsRehash := s.verifyUnderLimit(r.Context(), phc, req.Password)
	if readErr != nil {
		// Refused for a reason found in phase 1. The verification above was
		// performed anyway, for its timing, and its result is discarded.
		refuse(readErr)
		return
	}

	// ---- phase 3: write ----------------------------------------------------

	var (
		resp    LoginResponse
		token   string
		csrfTok string
		denied  error
	)
	err := s.db.Write(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		if !matched {
			// Returns NIL so this transaction commits. The refusal is carried
			// out of the closure in `denied` instead — returning an error here
			// is what rolled the counter back and made the lockout inert.
			denied = errWrongPassword
			if err := (store.Credentials{}).RecordFailure(ctx, c, user.ID); err != nil {
				return err
			}
			// A DURABLE record of the attempt, not just a log line.
			//
			// A brute force otherwise left nothing behind that survives log
			// rotation, and nothing an operator can query alongside the actions
			// the account went on to take. The event names the user because this
			// branch is only reached once the account is known; the refusals
			// that happen before that point have no user to name, which is the
			// same reason they cannot be counted.
			id := user.ID
			return (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
				ActorID: &id, ActorType: store.ActorUser,
				Action: "auth.login_failed", ResourceType: "user", ResourceID: &id,
				Detail: map[string]any{"method": "local"},
			})
		}
		if err := (store.Credentials{}).RecordSuccess(ctx, c, user.ID); err != nil {
			return err
		}
		if needsRehash {
			// The stored hash used weaker parameters than this build asks for.
			// Rewritten now, while the plaintext is in hand — the only moment it
			// can be.
			upgraded, err := credential.Hash(req.Password)
			if err != nil {
				return err
			}
			if err := (store.Credentials{}).Set(ctx, c, user.ID, upgraded, cred.MustChange); err != nil {
				return err
			}
		}
		var err error
		token, csrfTok, resp, err = s.issueSession(ctx, c, r, user, cred.MustChange, "local", nil)
		return err
	})
	if err != nil {
		writeError(w, r, s.log, http.StatusInternalServerError, CodeInternal,
			"An unexpected error occurred.", err)
		return
	}
	if denied != nil {
		refuse(denied)
		return
	}

	ttl := time.Until(resp.ExpiresAt)
	http.SetCookie(w, s.sessionCookie(token, ttl))
	http.SetCookie(w, s.csrfCookie(csrfTok, ttl))
	writeJSON(w, r, s.log, http.StatusOK, resp)
}

// errRefused is a phase-1 refusal that is not a store error: the tenant is not
// on-prem, is not configured for local auth, or the user is not active. Kept
// distinct from a store sentinel so isInfrastructureError can tell a refusal
// from a fault without inspecting message text.
var errRefused = errors.New("api: login refused")

// verifyUnderLimit performs one argon2id verification, bounded.
//
// The bound is a second denial of service, separate from the pool one: at 64 MiB
// per verification, five hundred concurrent logins ask for 32 GiB. The
// semaphore makes the memory cost of an unauthenticated endpoint a constant of
// the deployment rather than a function of how many requests arrive.
//
// Waiting rather than refusing, because the wait is already bounded by the
// server's ReadTimeout, and refusing would hand an attacker a way to lock real
// operators out by keeping the semaphore busy.
func (s *Server) verifyUnderLimit(ctx context.Context, phc, password string) (matched, needsRehash bool) {
	select {
	case s.hashSem <- struct{}{}:
		defer func() { <-s.hashSem }()
	case <-ctx.Done():
		return false, false
	}

	ok, rehash, err := credential.Verify(phc, password)
	if err != nil {
		// A corrupt stored hash. Denies, and is logged where the request id can
		// be joined to it — this is a row an operator has to repair, not
		// something the caller did wrong.
		s.log.Error("stored password hash could not be decoded", "err", err)
		return false, false
	}
	return ok, rehash
}

// issueSession mints the tokens and writes the row. Shared by local login and
// the OIDC callback.
//
// method is REQUIRED and travels into the audit event, which is the fix for a
// defect an ADR-compliance pass found: this function used to hardcode
// {"method": "local"}, so every single-sign-on login wrote a durable audit row
// claiming a local password login had succeeded — on a SaaS tenant, where all
// three conditions for local auth are unsatisfiable. The OIDC callback wrote its
// own correct event as well, so each login produced two rows, one of them false,
// and an operator querying the audit log for local-auth use got a false positive
// on every SSO session. That is the invariant migration 0026's three-condition
// gate exists to make auditable, and it had stopped being auditable.
func (s *Server) issueSession(ctx context.Context, c *store.Conn, r *http.Request, user *store.User, mustChange bool, method string, detail map[string]any) (string, string, LoginResponse, error) {
	token, tokenHash, err := newToken()
	if err != nil {
		return "", "", LoginResponse{}, err
	}
	csrfTok, csrfHash, err := newToken()
	if err != nil {
		return "", "", LoginResponse{}, err
	}

	ip := clientIP(r)
	if _, err := (store.Sessions{}).Create(ctx, c, user.ID, tokenHash[:], csrfHash[:],
		s.cfg.SessionTTL, ip, truncate(r.UserAgent(), 512)); err != nil {
		return "", "", LoginResponse{}, err
	}

	if method == "" {
		// A caller that forgot would otherwise write an event whose method claim
		// is empty, which reads as "unknown" and is exactly the ambiguity the
		// hardcoded value produced.
		return "", "", LoginResponse{}, errors.New("api: issueSession requires an authentication method")
	}
	if detail == nil {
		detail = map[string]any{}
	}
	detail["method"] = method

	id := user.ID
	if err := (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
		ActorID: &id, ActorType: store.ActorUser,
		Action: "auth.session_issued", ResourceType: "user", ResourceID: &id,
		Detail: detail,
	}); err != nil {
		return "", "", LoginResponse{}, err
	}

	return token, csrfTok, LoginResponse{
		UserID:     user.ID.String(),
		Email:      user.Email,
		CSRFToken:  csrfTok,
		ExpiresAt:  time.Now().Add(s.cfg.SessionTTL),
		MustChange: mustChange,
	}, nil
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	sess, ok := sessionFrom(r.Context())
	if !ok {
		writeError(w, r, s.log, http.StatusInternalServerError, CodeInternal,
			"An unexpected error occurred.", errors.New("api: logout with no session"))
		return
	}
	tenant, _ := tenantFrom(r.Context())

	err := s.db.Write(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.Sessions{}).Revoke(ctx, c, sess.ID, "logout")
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}
	http.SetCookie(w, s.expiredCookie(SessionCookie, true))
	http.SetCookie(w, s.expiredCookie(CSRFCookie, false))
	writeJSON(w, r, s.log, http.StatusNoContent, nil)
}

func (s *Server) currentSession(w http.ResponseWriter, r *http.Request) {
	sess, ok := sessionFrom(r.Context())
	if !ok {
		writeError(w, r, s.log, http.StatusInternalServerError, CodeInternal,
			"An unexpected error occurred.", errors.New("api: session route with no session"))
		return
	}
	perms := permissionsFrom(r.Context())
	names := make([]string, 0, len(perms))
	for _, p := range PermissionNames() {
		if perms.Has(p) {
			names = append(names, string(p))
		}
	}
	writeJSON(w, r, s.log, http.StatusOK, SessionResponse{
		UserID: sess.UserID.String(), Email: sess.Email, RoleID: sess.RoleID.String(),
		Permissions: names, ExpiresAt: sess.ExpiresAt,
	})
}

// ChangePasswordRequest is the body of POST /v1/auth/password.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// MinPasswordLength is the only password rule.
//
// Length and nothing else: no character-class requirement, no forced rotation.
// Composition rules push people toward predictable substitutions and toward
// writing the result down, which is the position NIST SP 800-63B reached and the
// reason argon2id is doing the actual work here.
const MinPasswordLength = 12

// changePassword is split the same three ways as login, for the same two
// reasons: the argon2 work must not hold a pooled connection, and a failure must
// be counted in a transaction that commits.
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	var req ChangePasswordRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"The request body could not be read as this endpoint's schema.", err)
		return
	}
	if len(req.NewPassword) < MinPasswordLength {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"A password must be at least 12 characters.", nil)
		return
	}

	sess, _ := sessionFrom(r.Context())
	tenant, _ := tenantFrom(r.Context())

	var cred *store.Credential
	if err := s.db.Read(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		cred, err = (store.Credentials{}).Get(ctx, c, sess.UserID)
		return err
	}); err != nil {
		if errors.Is(err, store.ErrCredentialLocked) || errors.Is(err, store.ErrNotFound) {
			writeError(w, r, s.log, http.StatusUnauthorized, CodeUnauthorized,
				"Those credentials are not valid.", err)
			return
		}
		storeError(w, r, s.log, err)
		return
	}

	// Both hashes outside any transaction: the verification of the current
	// password and the derivation of the new one.
	matched, _ := s.verifyUnderLimit(r.Context(), cred.PasswordHash, req.CurrentPassword)
	var phc string
	if matched {
		var err error
		if phc, err = credential.Hash(req.NewPassword); err != nil {
			writeError(w, r, s.log, http.StatusInternalServerError, CodeInternal,
				"An unexpected error occurred.", err)
			return
		}
	}

	var denied error
	err := s.db.Write(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		if !matched {
			// The current password is required even for a must-change session.
			// A must-change flag means somebody set a password for this account;
			// it does not mean whoever holds the session may replace it without
			// knowing what it is.
			//
			// nil, so the counter commits. See login.
			denied = errWrongPassword
			return (store.Credentials{}).RecordFailure(ctx, c, sess.UserID)
		}
		if err := (store.Credentials{}).Set(ctx, c, sess.UserID, phc, false); err != nil {
			return err
		}
		// Every OTHER session ends, including this one. A password changed
		// because it was stolen must not leave the thief's session alive, and
		// the only way to be sure which sessions are the thief's is to end all
		// of them.
		if err := (store.Sessions{}).RevokeAllForUser(ctx, c, sess.UserID, "password changed"); err != nil {
			return err
		}
		id := sess.UserID
		return (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
			ActorID: &id, ActorType: store.ActorUser,
			Action: "auth.password_changed", ResourceType: "user", ResourceID: &id,
		})
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}
	if denied != nil {
		writeError(w, r, s.log, http.StatusUnauthorized, CodeUnauthorized,
			"Those credentials are not valid.", denied)
		return
	}

	http.SetCookie(w, s.expiredCookie(SessionCookie, true))
	http.SetCookie(w, s.expiredCookie(CSRFCookie, false))
	writeJSON(w, r, s.log, http.StatusNoContent, nil)
}

var errWrongPassword = errors.New("api: password mismatch")

func isInfrastructureError(err error) bool {
	// A store sentinel is an outcome; anything else that reaches the login
	// transaction is a fault. ErrNotFound is the "no such user" case and
	// belongs on the refusal side.
	switch {
	case errors.Is(err, store.ErrNotFound),
		errors.Is(err, store.ErrCredentialLocked),
		errors.Is(err, store.ErrSessionInvalid):
		return false
	case errors.Is(err, store.ErrNotPermitted),
		errors.Is(err, store.ErrTenantIsolation),
		errors.Is(err, store.ErrNoTenantContext),
		errors.Is(err, store.ErrTransactionEnded),
		errors.Is(err, store.ErrConnReleased):
		return true
	}
	// A bare errors.New from the checks above this function's callers — the
	// deployment-mode and auth-method refusals — is a refusal, not a fault.
	return false
}

func clientIP(r *http.Request) *string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return nil
	}
	return &host
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
