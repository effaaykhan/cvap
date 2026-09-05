package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/store"
)

// The middleware chain, in the order the architecture's API gateway states:
// tenant resolution, then authentication, then authorisation.
//
// ============================================================================
// The tenant comes from the request HOST. It is never read from the request.
// ============================================================================
//
// Not from a body field, not from a header, not from a query parameter, not from
// a claim in a token. ADR-041 gives the reasoning; the mechanism is that no code
// in this package reads a tenant from anywhere except tenantFrom(ctx), which is
// populated by exactly one function, from exactly one input.

// Cookie and header names.
const (
	SessionCookie = "cvap_session"

	// The CSRF token is delivered in a READABLE cookie and echoed in a header.
	// The session cookie stays HttpOnly; this one cannot be, because the page
	// has to read it. That is the whole double-submit construction: an attacker
	// on another origin can cause the session cookie to be sent but cannot read
	// this one to set the header.
	CSRFCookie = "cvap_csrf"
	CSRFHeader = "X-CVAP-CSRF"

	RequestIDHeader = "X-Request-Id"
)

type ctxKey int

const (
	ctxTenant ctxKey = iota
	ctxSession
	ctxPermissions
	ctxRequestID
	ctxUnresolved
)

func tenantFrom(ctx context.Context) (store.TenantID, bool) {
	t, ok := ctx.Value(ctxTenant).(store.TenantID)
	return t, ok
}

func sessionFrom(ctx context.Context) (*store.Session, bool) {
	s, ok := ctx.Value(ctxSession).(*store.Session)
	return s, ok
}

func permissionsFrom(ctx context.Context) PermissionSet {
	p, _ := ctx.Value(ctxPermissions).(PermissionSet)
	return p
}

func requestIDFrom(ctx context.Context) string {
	s, _ := ctx.Value(ctxRequestID).(string)
	return s
}

// withRequestID assigns an id to every request.
//
// Generated here rather than taken from the inbound header, even though the
// header is echoed back. A client-supplied id in a log is a client-supplied
// string in a log, which is a way to forge or to confuse an audit trail; the
// inbound value is recorded as a separate field if present.
func (s *Server) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := uuid.NewString()
		w.Header().Set(RequestIDHeader, id)
		ctx := context.WithValue(r.Context(), ctxRequestID, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// securityHeaders sets the class-of-response headers that every path must carry,
// wrapping the mux so it covers ALL of them — the JSON API, the CSV export, and
// the static SPA alike.
//
// It lives here, in one middleware, rather than in writeJSON, because that is
// where it used to live and the static SPA path (spa.go) does not go through
// writeJSON — so it shipped serving the operator console, the one origin that
// executes JavaScript and renders scan-target-derived data, with none of these.
// A per-write helper cannot cover a handler that does not call it; a
// mux-wrapping middleware covers every handler including the next one nobody
// remembers to protect.
//
// Set BEFORE next.ServeHTTP so they are in the header map when the handler
// writes its status; a handler that needs a different value for a
// response-specific header (Content-Type, Cache-Control, Content-Disposition)
// still overrides it, which is why those are NOT set here.
//
//   - nosniff: a body a browser decides to treat as HTML is a stored-XSS vector
//     out of any field an operator can set — and the served JS/CSS must not be
//     re-typed either.
//   - CSP: the containment layer for the console. Everything it loads is
//     same-origin (an external module script and stylesheet, no inline script
//     or style, no data: assets — measured against the build), so 'self' is the
//     whole policy; it blunts any future XSS or a compromised dependency, and
//     is inert-but-harmless on the JSON responses that are never rendered.
//   - X-Frame-Options / frame-ancestors: nothing here is ever framed, and the
//     kill switch in particular must not be clickjackable.
//   - HSTS: the session cookie is a bearer credential and the first plaintext
//     request is the one that leaks it.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("Content-Security-Policy",
			"default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'")
		next.ServeHTTP(w, r)
	})
}

// resolveTenant is the first thing every request meets.
//
// It runs on public routes too. A public route is unauthenticated, not
// untenanted: the login endpoint has to know which tenant's users it is about
// before it can look one up, and that is precisely why the host is what carries
// it.
//
// ============================================================================
// An unresolvable host is refused the way an unauthenticated request is.
// ============================================================================
//
// It used to answer 404 while every live tenant's login refusal was 401, which
// walked the customer list on a SaaS deployment with wildcard DNS: post junk
// credentials at a hostname and read the status code. tenant_for_domain returns
// the same NULL for unknown, suspended and closed — and then the response threw
// the indistinguishability away.
//
// So resolution failure is CARRIED rather than answered. It reaches the same
// refusal an unknown password reaches, from the same handler, with the same
// status and the same body. The log records which it was; the caller cannot
// tell.
func (s *Server) resolveTenant(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenant, err := s.db.ResolveDomainTenant(r.Context(), r.Host)
		if err != nil {
			if !errors.Is(err, store.ErrTenantNotResolved) {
				writeError(w, r, s.log, http.StatusInternalServerError, CodeInternal,
					"An unexpected error occurred.", err)
				return
			}
			s.log.Info("host did not resolve to a tenant",
				"request_id", requestIDFrom(r.Context()), "host", r.Host)
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxUnresolved, true)))
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxTenant, tenant)))
	})
}

// unresolved reports whether the request host named no active tenant.
func unresolved(ctx context.Context) bool {
	v, _ := ctx.Value(ctxUnresolved).(bool)
	return v
}

// authenticate resolves the session cookie, for routes that need one.
//
// One failure response for every way it can fail — absent, malformed, unknown,
// expired, revoked, or belonging to a user who has been disabled. store.Sessions
// already collapses those into one sentinel; this preserves that rather than
// re-expanding it.
func (s *Server) authenticate(r Route, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r2 *http.Request) {
		// Cross-origin refusal, BEFORE the public shortcut.
		//
		// A public mutating route has no session, so it has no CSRF token to
		// bind to — and POST /v1/auth/login is exactly that. Without this, a
		// third-party page could log a victim's browser into an ATTACKER's
		// account: SameSite=Lax governs whether a cookie is sent, not whether a
		// Set-Cookie on a cross-site POST response is honoured. In this product
		// the consequence is that the victim's subsequent scans, kill-switch
		// actions and enrollment tokens land in the attacker's account.
		if r.Mutating() && !sameOrigin(r2) {
			writeError(w, r2, s.log, http.StatusForbidden, CodeForbidden,
				"This request did not come from this site.",
				errors.New("api: cross-origin mutating request"))
			return
		}

		if r.Access == AccessPublic {
			next.ServeHTTP(w, r2)
			return
		}

		if unresolved(r2.Context()) {
			// The host named no active tenant. Answered identically to a request
			// with no session, which is what keeps the two indistinguishable —
			// see resolveTenant.
			s.unauthorized(w, r2, errors.New("api: host resolved to no tenant"))
			return
		}

		tenant, ok := tenantFrom(r2.Context())
		if !ok {
			// Unreachable through the chain, and checked anyway: the cost is a
			// branch, and the failure it catches is a handler running with no
			// tenant, which is the one failure RLS cannot help with.
			writeError(w, r2, s.log, http.StatusInternalServerError, CodeInternal,
				"An unexpected error occurred.", errors.New("api: no tenant in context after resolution"))
			return
		}

		cookie, err := r2.Cookie(SessionCookie)
		if err != nil || cookie.Value == "" {
			s.unauthorized(w, r2, errors.New("api: no session cookie"))
			return
		}
		sum := sha256.Sum256([]byte(cookie.Value))

		var sess *store.Session
		err = s.db.Write(r2.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
			var err error
			sess, err = (store.Sessions{}).Lookup(ctx, c, sum[:])
			if err != nil {
				return err
			}
			// Write rather than Read because of this: last_seen_at is what an
			// operator's session list shows. It does NOT extend expiry — the
			// 12-hour cap is a CHECK constraint on the row, not a policy this
			// code could relax by accident.
			return (store.Sessions{}).Touch(ctx, c, sess.ID)
		})
		if err != nil {
			if errors.Is(err, store.ErrSessionInvalid) {
				s.unauthorized(w, r2, err)
				return
			}
			writeError(w, r2, s.log, http.StatusInternalServerError, CodeInternal,
				"An unexpected error occurred.", err)
			return
		}

		// CSRF, on every mutating request, before the handler runs.
		//
		// Checked here rather than per handler for the reason the permission is:
		// a check a handler performs is a check a handler can omit, and the
		// omission looks like nothing at all in a diff.
		//
		// The cross-origin check above this one covers the PUBLIC mutating
		// routes, which have no session to bind a token to.
		if r.Mutating() && !s.csrfOK(r2, sess) {
			writeError(w, r2, s.log, http.StatusForbidden, CodeForbidden,
				"Missing or invalid CSRF token.", errors.New("api: csrf check failed"))
			return
		}

		perms, err := ParsePermissions(sess.Permissions)
		if err != nil {
			// Corrupt permissions deny, and say so loudly. Treating them as an
			// empty set would also deny, but silently, and an operator whose
			// access vanished would have nothing to look at.
			writeError(w, r2, s.log, http.StatusInternalServerError, CodeInternal,
				"An unexpected error occurred.", err)
			return
		}

		// A password that must change gates everything except changing it.
		// Enforced centrally, so a route added later cannot be reachable with a
		// credential an operator has already marked as needing replacement.
		if sess.MustChange && !isPasswordChange(r) {
			writeError(w, r2, s.log, http.StatusForbidden, CodeForbidden,
				"This password must be changed before anything else can be done.", nil)
			return
		}

		ctx := context.WithValue(r2.Context(), ctxSession, sess)
		ctx = context.WithValue(ctx, ctxPermissions, perms)
		next.ServeHTTP(w, r2.WithContext(ctx))
	})
}

// authorize checks the route's permission.
func (s *Server) authorize(r Route, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r2 *http.Request) {
		if r.Access != AccessPermission {
			next.ServeHTTP(w, r2)
			return
		}
		if !permissionsFrom(r2.Context()).Has(r.Permission) {
			sess, _ := sessionFrom(r2.Context())
			var user string
			if sess != nil {
				user = sess.UserID.String()
			}
			s.log.Info("permission denied",
				"request_id", requestIDFrom(r2.Context()),
				"user_id", user, "permission", string(r.Permission),
				"method", r2.Method, "path", r2.URL.Path)
			writeError(w, r2, s.log, http.StatusForbidden, CodeForbidden,
				"This account does not hold the permission this operation requires.", nil)
			return
		}
		next.ServeHTTP(w, r2)
	})
}

// csrfOK is the double-submit check.
//
// Constant-time comparison, because the value is a secret bound to the session
// and a timing-variable comparison against a secret is a timing-variable
// comparison against a secret whatever it is protecting.
func (s *Server) csrfOK(r *http.Request, sess *store.Session) bool {
	sent := r.Header.Get(CSRFHeader)
	if sent == "" {
		return false
	}
	sum := sha256.Sum256([]byte(sent))
	return subtle.ConstantTimeCompare(sum[:], sess.CSRFHash) == 1
}

func (s *Server) unauthorized(w http.ResponseWriter, r *http.Request, cause error) {
	// The cookie is cleared on the way out, so a client holding a session that
	// is no longer valid stops sending it. Without this a revoked session
	// produces a 401 on every subsequent request forever.
	http.SetCookie(w, s.expiredCookie(SessionCookie, true))
	http.SetCookie(w, s.expiredCookie(CSRFCookie, false))
	writeError(w, r, s.log, http.StatusUnauthorized, CodeUnauthorized,
		"Sign in again.", cause)
}

// isPasswordChange identifies the one route a must-change session may reach.
func isPasswordChange(r Route) bool {
	return r.Method == http.MethodPost && r.Path == "/v1/auth/password"
}

// sameOrigin reports whether a mutating request came from this site.
//
// Two independent signals, and ABSENCE of both is permitted. That is deliberate
// rather than lax: neither header is sent by curl, by a CLI, or by an older
// browser, and refusing a request that carries neither would break every
// non-browser client while stopping nothing — a cross-site form post from a
// browser always carries Origin.
//
//   - Sec-Fetch-Site is the stronger signal, sent by current browsers and not
//     settable by script. cross-site and same-site are both refused: a sibling
//     hostname is a different tenant here, which is precisely the boundary that
//     matters.
//   - Origin is checked against the request host. It is what older browsers send
//     and what a cross-site form post carries.
func sameOrigin(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		// "none" is a user-initiated navigation — typing the URL, a bookmark —
		// which no other page can cause.
		return true
	case "":
		// Not sent. Fall through to Origin.
	default:
		return false
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}
