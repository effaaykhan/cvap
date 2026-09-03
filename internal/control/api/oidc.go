package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/effaaykhan/cvap/internal/store"
)

// OpenID Connect, authorization code flow with PKCE.
//
// ============================================================================
// The tenant is resolved from the HOST before the identity provider is chosen,
// and the callback cannot name its own tenant.
// ============================================================================
//
// That is the property the whole chain rests on, and the callback is the one
// endpoint in this API that takes attacker-shaped input from a third party. Both
// halves of the flow run behind the same resolveTenant middleware every other
// route runs behind, so:
//
//   - which issuer to send a browser to is read from THIS tenant's
//     tenant_auth_config, never from a request parameter;
//   - the state presented at the callback is consumed inside a transaction
//     opened for the tenant the callback's HOSTNAME resolved to, so a state
//     minted at tenant A and replayed at tenant B is a row RLS does not show;
//   - `iss` and `aud` on the ID token are checked against THIS tenant's
//     configuration rather than against any tenant's, because the verifier is
//     built from the config that was just read.
//
// There is no tenant parameter anywhere in this file, and TestNoRouteAcceptsATenant
// asserts that no schema in this package grows one.

// authRequestTTL is how long a browser has to complete a login.
const authRequestTTL = 10 * time.Minute

// providerCacheTTL bounds how long a discovery document is reused.
//
// Discovery and JWKS are network fetches inside a login request. Doing them per
// login makes every sign-in wait on someone else's service and hammers it; go-oidc's
// RemoteKeySet does its own key caching and refresh, so what is cached here is
// the provider — the endpoints and the supported algorithms.
const providerCacheTTL = time.Hour

type cachedProvider struct {
	provider  *oidc.Provider
	endpoints struct {
		Authorization string `json:"authorization_endpoint"`
		Token         string `json:"token_endpoint"`

		// JWKS is here ONLY so the https check below covers it.
		//
		// go-oidc fetches it itself and does not check the scheme, and the first
		// version of that check listed the other two and omitted this one — so a
		// discovery document naming an http jwks_uri completed a login, with the
		// signing keys arriving in cleartext. Those keys are the root of every
		// signature check: an on-path attacker who substitutes the key set forges
		// an ID token for any subject at that issuer.
		JWKS string `json:"jwks_uri"`
	}
	fetchedAt time.Time
}

// providerCache is keyed by ISSUER, not by tenant.
//
// Two tenants federating with the same identity provider — a managed service
// provider and its customer, two subsidiaries — share one discovery document and
// one key set, which is a property of the issuer. What must NOT be shared is the
// client id and the audience check, and those are not in here: they come from
// each tenant's own config every time a verifier is built.
type providerCache struct {
	mu sync.Mutex
	by map[string]*cachedProvider
}

func newProviderCache() *providerCache { return &providerCache{by: map[string]*cachedProvider{}} }

func (pc *providerCache) get(ctx context.Context, client *http.Client, issuer string) (*cachedProvider, error) {
	pc.mu.Lock()
	entry, ok := pc.by[issuer]
	pc.mu.Unlock()
	if ok && time.Since(entry.fetchedAt) < providerCacheTTL {
		return entry, nil
	}

	// Discovery runs with the hardened client, which is what stops an
	// operator-supplied issuer reaching the cloud metadata service. See
	// oidc_client.go.
	p, err := oidc.NewProvider(oidc.ClientContext(ctx, client), issuer)
	if err != nil {
		return nil, fmt.Errorf("api: oidc discovery for %s: %w", issuer, err)
	}
	fresh := &cachedProvider{provider: p, fetchedAt: time.Now()}
	if err := p.Claims(&fresh.endpoints); err != nil {
		return nil, fmt.Errorf("api: oidc discovery document for %s: %w", issuer, err)
	}
	if fresh.endpoints.Authorization == "" || fresh.endpoints.Token == "" || fresh.endpoints.JWKS == "" {
		return nil, fmt.Errorf("api: oidc discovery for %s is missing an authorization, token or jwks endpoint", issuer)
	}
	// Both endpoints must be https. Discovery came over TLS from the issuer, so
	// a plaintext endpoint in it is either a misconfigured provider or one whose
	// document has been tampered with, and the authorization code would travel
	// in the clear either way.
	for _, e := range []string{fresh.endpoints.Authorization, fresh.endpoints.Token, fresh.endpoints.JWKS} {
		u, err := url.Parse(e)
		if err != nil || u.Scheme != "https" {
			return nil, fmt.Errorf("api: oidc endpoint %q for %s is not https", e, issuer)
		}
	}

	pc.mu.Lock()
	pc.by[issuer] = fresh
	pc.mu.Unlock()
	return fresh, nil
}

// StartOIDCResponse is what the start endpoint returns.
type StartOIDCResponse struct {
	// AuthorizationURL is where the browser goes next. Returned in a body rather
	// than as a 302 so a single-page application can drive the redirect itself
	// and so a CLI can print it.
	AuthorizationURL string `json:"authorization_url"`
}

// startOIDC begins a login.
func (s *Server) startOIDC(w http.ResponseWriter, r *http.Request) {
	tenant, haveTenant := tenantFrom(r.Context())

	// Same single refusal as local login, and for the same reason: this runs
	// before authentication, so anything it distinguishes is something an
	// unauthenticated caller learns — including whether a hostname is a
	// configured tenant at all.
	refuse := func(cause error) {
		attrs := []any{"request_id", requestIDFrom(r.Context()), "reason", cause.Error()}
		if haveTenant {
			attrs = append(attrs, "tenant_id", tenant.String())
		} else {
			attrs = append(attrs, "host", r.Host)
		}
		s.log.Info("oidc start refused", attrs...)
		writeError(w, r, s.log, http.StatusUnauthorized, CodeUnauthorized,
			"Single sign-on is not available here.", nil)
	}

	if !haveTenant {
		refuse(errors.New("host resolved to no tenant"))
		return
	}

	// The path to return to after login. A PATH, validated here and constrained
	// again by a CHECK on the column: an absolute URL would make this callback
	// an open redirect, which is a phishing primitive that borrows this
	// deployment's hostname and its TLS certificate.
	returnPath := "/"
	if v := r.URL.Query().Get("return_to"); v != "" {
		if !isSafeReturnPath(v) {
			writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
				"return_to must be a path on this site.", nil)
			return
		}
		returnPath = v
	}

	var cfg *store.AuthConfig
	if err := s.db.Read(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		cfg, err = (store.AuthConfigs{}).Get(ctx, c)
		return err
	}); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			refuse(errors.New("tenant has no auth configuration"))
			return
		}
		writeError(w, r, s.log, http.StatusInternalServerError, CodeInternal,
			"An unexpected error occurred.", err)
		return
	}
	if cfg.Method != store.AuthOIDC {
		refuse(fmt.Errorf("tenant authenticates with %s", cfg.Method))
		return
	}

	prov, err := s.providers.get(r.Context(), s.oidcClient, cfg.OIDCIssuer)
	if err != nil {
		// A provider that is down is OUR problem to see, not the caller's to
		// diagnose: the response says single sign-on is unavailable and the log
		// says which issuer and why.
		s.log.Error("oidc discovery failed",
			"request_id", requestIDFrom(r.Context()), "tenant_id", tenant.String(),
			"issuer", cfg.OIDCIssuer, "err", err)
		writeError(w, r, s.log, http.StatusBadGateway, CodeInternal,
			"Single sign-on is temporarily unavailable.", err)
		return
	}

	state, stateHash, err := newToken()
	if err != nil {
		writeError(w, r, s.log, http.StatusInternalServerError, CodeInternal,
			"An unexpected error occurred.", err)
		return
	}
	nonce, nonceHash, err := newToken()
	if err != nil {
		writeError(w, r, s.log, http.StatusInternalServerError, CodeInternal,
			"An unexpected error occurred.", err)
		return
	}
	verifier, challenge, err := newPKCE()
	if err != nil {
		writeError(w, r, s.log, http.StatusInternalServerError, CodeInternal,
			"An unexpected error occurred.", err)
		return
	}
	// The browser binding. See the column comment in migration 0029: state gives
	// single-use, this gives user-agent binding, and the flow needs both.
	browserTok, browserHash, err := newToken()
	if err != nil {
		writeError(w, r, s.log, http.StatusInternalServerError, CodeInternal,
			"An unexpected error occurred.", err)
		return
	}

	// The redirect_uri is DERIVED from the tenant's own domain, server-side.
	//
	// Never from a request parameter and never from the Host header directly:
	// tenants.domain is what tenant_for_domain matched, so it is the one value
	// that is both this tenant's and not the caller's to choose. An attacker who
	// could influence it would receive the authorization code.
	redirectURI, err := s.redirectURI(r.Context(), tenant)
	if err != nil {
		writeError(w, r, s.log, http.StatusInternalServerError, CodeInternal,
			"An unexpected error occurred.", err)
		return
	}

	if err := s.db.Write(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := (store.OIDCAuthRequests{}).Create(ctx, c,
			stateHash[:], nonceHash[:], browserHash[:], verifier, redirectURI, returnPath, authRequestTTL)
		return err
	}); err != nil {
		if errors.Is(err, store.ErrTooManyAuthRequests) {
			// A flood, or a sweeper that has stopped purging. Loud, because the
			// second reading is an outage in a component nothing else watches.
			s.log.Warn("oidc login attempts are at the per-tenant ceiling",
				"request_id", requestIDFrom(r.Context()), "tenant_id", tenant.String())
			writeError(w, r, s.log, http.StatusTooManyRequests, CodeConflict,
				"Too many sign-in attempts are in flight. Try again shortly.", err)
			return
		}
		writeError(w, r, s.log, http.StatusInternalServerError, CodeInternal,
			"An unexpected error occurred.", err)
		return
	}

	http.SetCookie(w, s.oidcBindingCookie(browserTok, authRequestTTL))

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {cfg.OIDCClientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid email profile"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	sep := "?"
	if strings.Contains(prov.endpoints.Authorization, "?") {
		sep = "&"
	}
	writeJSON(w, r, s.log, http.StatusOK, StartOIDCResponse{
		AuthorizationURL: prov.endpoints.Authorization + sep + q.Encode(),
	})
}

// callbackOIDC completes a login.
//
// This is the one endpoint in the API that takes input from a third party's
// redirect, so every value in it is treated as attacker-chosen: `state` is a
// lookup key inside this tenant's scope and nothing else, `code` is only ever
// sent back to the issuer's own token endpoint, and the ID token is verified
// against this tenant's configuration before a single claim is read.
func (s *Server) callbackOIDC(w http.ResponseWriter, r *http.Request) {
	tenant, haveTenant := tenantFrom(r.Context())

	refuse := func(cause error) {
		attrs := []any{"request_id", requestIDFrom(r.Context()), "reason", cause.Error()}
		if haveTenant {
			attrs = append(attrs, "tenant_id", tenant.String())
		} else {
			attrs = append(attrs, "host", r.Host)
		}
		s.log.Info("oidc callback refused", attrs...)
		writeError(w, r, s.log, http.StatusUnauthorized, CodeUnauthorized,
			"That sign-in could not be completed.", nil)
	}

	if !haveTenant {
		refuse(errors.New("host resolved to no tenant"))
		return
	}

	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		// The identity provider refused. Logged with its reason and reported
		// without it: the string comes from a third party and lands in a
		// browser.
		// TRUNCATED. Both fields are third-party text on an unauthenticated
		// path: one callback wrote 200 KB of log from error_description in a
		// review probe, which is a way to fill a disk with a GET.
		s.log.Info("identity provider refused the authorization",
			"request_id", requestIDFrom(r.Context()), "tenant_id", tenant.String(),
			"error", truncate(e, 256), "description", truncate(q.Get("error_description"), 512))
		refuse(fmt.Errorf("identity provider returned error=%s", e))
		return
	}

	state, code := q.Get("state"), q.Get("code")
	if state == "" || code == "" {
		refuse(errors.New("callback carried no state or no code"))
		return
	}
	stateHash := sha256.Sum256([]byte(state))

	// The binding cookie.
	//
	// Its absence is the attack: a victim's browser directed at a callback URL
	// the attacker assembled has no cookie from OUR /start, because it never
	// called it. An attacker can cause a request; they cannot make it send a
	// cookie their own browser received.
	//
	// ABSENT and WRONG take one path, deliberately. An early return on absence
	// would leave the state unconsumed while a wrong value consumed it, which
	// makes the two distinguishable by whether a retry then works — and gives an
	// attacker a free probe. An empty string compares unequal to any hash, so
	// falling through handles both.
	var bindingValue string
	if c, err := r.Cookie(s.oidcBindingName()); err == nil {
		bindingValue = c.Value
	}
	s.clearOIDCBinding(w)

	// Consumed FIRST, before the code is exchanged.
	//
	// Single-use has to be won before anything expensive or observable happens.
	// Exchanging first and consuming after would let a replayed state be
	// exchanged twice concurrently, and each exchange is a request to the IdP
	// that an attacker can therefore cause.
	var (
		req      *store.OIDCAuthRequest
		cfg      *store.AuthConfig
		mismatch bool
	)
	if err := s.db.Write(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		if req, err = (store.OIDCAuthRequests{}).Consume(ctx, c, stateHash[:]); err != nil {
			return err
		}
		// ============================================================================
		// Sets a flag and returns NIL, so the DELETE commits.
		// ============================================================================
		//
		// Returning an error here rolls the transaction back, which un-deletes
		// the row — so a wrong binding left the state redeemable and a second
		// callback with the right cookie succeeded. My own regression test
		// caught it, and it is the same shape as the lockout counter a security
		// review found last session: a control performed inside a transaction
		// that is then aborted by the refusal it triggered.
		//
		// A failed binding check must cost the attempt. Otherwise an attacker who
		// can cause one callback can cause a second.
		if !constantTimeEqualHash(bindingValue, req.BrowserHash) {
			mismatch = true
			return nil
		}
		cfg, err = (store.AuthConfigs{}).Get(ctx, c)
		return err
	}); err != nil {
		if errors.Is(err, store.ErrAuthRequestInvalid) || errors.Is(err, store.ErrNotFound) {
			refuse(err)
			return
		}
		writeError(w, r, s.log, http.StatusInternalServerError, CodeInternal,
			"An unexpected error occurred.", err)
		return
	}
	if mismatch {
		s.log.Warn("oidc callback presented the wrong browser binding",
			"request_id", requestIDFrom(r.Context()), "tenant_id", tenant.String())
		refuse(errBrowserMismatch)
		return
	}
	if cfg.Method != store.AuthOIDC {
		// The tenant switched away from OIDC while this login was in flight.
		refuse(fmt.Errorf("tenant authenticates with %s", cfg.Method))
		return
	}

	prov, err := s.providers.get(r.Context(), s.oidcClient, cfg.OIDCIssuer)
	if err != nil {
		s.log.Error("oidc discovery failed at callback",
			"request_id", requestIDFrom(r.Context()), "issuer", cfg.OIDCIssuer, "err", err)
		writeError(w, r, s.log, http.StatusBadGateway, CodeInternal,
			"Single sign-on is temporarily unavailable.", err)
		return
	}

	rawIDToken, err := s.exchangeCode(r.Context(), prov.endpoints.Token, cfg.OIDCClientID, code, req.CodeVerifier, req.RedirectURI)
	if err != nil {
		// A TRANSPORT failure is an outage, and gets the same 502 discovery
		// does. The two were conflated: ADR-046 claimed "an identity provider
		// being down is a 502, not a 401", which was true of discovery and false
		// of the exchange — so a provider that went down between the redirect
		// and the callback presented as "that sign-in could not be completed"
		// with nothing at Error level and no issuer in the log. That is exactly
		// the confusion the sentence said it prevented.
		if errors.Is(err, errIDPUnreachable) {
			s.log.Error("identity provider unreachable at the token exchange",
				"request_id", requestIDFrom(r.Context()), "tenant_id", tenant.String(),
				"issuer", cfg.OIDCIssuer, "err", err)
			writeError(w, r, s.log, http.StatusBadGateway, CodeInternal,
				"Single sign-on is temporarily unavailable.", err)
			return
		}
		// A protocol refusal — the provider answered and said no — is the
		// caller's problem and refuses like any other bad credential.
		s.log.Info("oidc token exchange refused",
			"request_id", requestIDFrom(r.Context()), "tenant_id", tenant.String(), "err", err)
		refuse(err)
		return
	}

	// ============================================================================
	// Verified against THIS tenant's configuration, not against any tenant's.
	// ============================================================================
	//
	// The verifier is built from cfg, which came from the row this tenant owns,
	// so `aud` is checked against this tenant's client id and `iss` against this
	// tenant's issuer. Building it from a shared or cached client id would mean a
	// token minted for tenant A's client verifying at tenant B — which is the
	// cross-tenant hole the whole host-first chain exists to close, reappearing
	// at the last step.
	verifier := prov.provider.Verifier(&oidc.Config{
		ClientID: cfg.OIDCClientID,
		// Asymmetric only. Permitting a MAC algorithm is how algorithm confusion
		// works: an attacker signs a token with HS256 using the provider's PUBLIC
		// key as the shared secret, and a verifier that accepts both families
		// validates it.
		SupportedSigningAlgs: []string{
			oidc.RS256, oidc.RS384, oidc.RS512,
			oidc.ES256, oidc.ES384, oidc.ES512,
			oidc.PS256, oidc.PS384, oidc.PS512,
		},
	})
	idToken, err := verifier.Verify(oidc.ClientContext(r.Context(), s.oidcClient), rawIDToken)
	if err != nil {
		s.log.Info("id token verification failed",
			"request_id", requestIDFrom(r.Context()), "tenant_id", tenant.String(), "err", err)
		refuse(err)
		return
	}

	// azp, when the audience is multi-valued.
	//
	// OIDC Core 3.1.3.7 step 4: a token whose `aud` names several clients must
	// carry `azp` naming the one it was issued to, and go-oidc checks only that
	// our client id appears SOMEWHERE in `aud`. Without this, a token minted for
	// another client at the same issuer — which on a shared-issuer deployment is
	// another tenant's — is accepted here as long as it also lists ours.
	if len(idToken.Audience) > 1 {
		var azpClaim struct {
			AZP string `json:"azp"`
		}
		if err := idToken.Claims(&azpClaim); err != nil || azpClaim.AZP != cfg.OIDCClientID {
			refuse(fmt.Errorf("id token has a multi-valued audience and azp %q, want %q",
				azpClaim.AZP, cfg.OIDCClientID))
			return
		}
	}

	// The nonce, compared to the one minted for THIS login attempt.
	//
	// go-oidc does not check it — the library cannot know what was minted — so a
	// verifier without this accepts any valid token from the issuer, including
	// one replayed from a different login or obtained for a different
	// application. Constant time, because it is a secret.
	if !constantTimeEqualHash(idToken.Nonce, req.NonceHash) {
		refuse(errors.New("id token nonce does not match the login attempt"))
		return
	}

	// ============================================================================
	// email_verified describes the `email` claim, and nothing else.
	// ============================================================================
	//
	// OIDC Core 5.1 defines it as a statement about `email`. The first version
	// read the ADDRESS from a configurable claim and the VERIFICATION always from
	// `email_verified` — so with oidc_email_claim = "upn", a token asserting
	// `email: mallory@…` with `email_verified: true` alongside `upn: op@…` linked
	// the attacker's subject to the operator's account, permanently. A security
	// review measured it. Worse, a token with no `upn` at all fell through to the
	// `email` value, which is the claim the operator overrode precisely because
	// they did not trust it.
	//
	// So a configured claim brings its own verification claim, and an absent one
	// is a refusal rather than a fallback.
	email, emailVerified, err := s.addressFromClaims(idToken, cfg.OIDCEmailClaim)
	if err != nil {
		refuse(err)
		return
	}

	var (
		user    *store.User
		token   string
		csrfTok string
		resp    LoginResponse
		denied  error
	)
	err = s.db.Write(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		user, err = s.resolveOIDCUser(ctx, c, cfg, idToken.Subject, email, emailVerified)
		if err != nil {
			if errors.Is(err, errOIDCNoAccount) {
				denied = err
				return nil
			}
			return err
		}
		// ONE event, written by issueSession, which now takes the method. This
		// used to record its own here as well, so every SSO login left two rows
		// and the second claimed the method was "local".
		token, csrfTok, resp, err = s.issueSession(ctx, c, r, user, false, "oidc",
			map[string]any{"issuer": cfg.OIDCIssuer, "subject": idToken.Subject})
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

	// ============================================================================
	// The guard runs on the input; http.Redirect rewrites the output.
	// ============================================================================
	//
	// isSafeReturnPath refuses `/\evil.test` because browsers normalise the
	// backslash to `//`. http.Redirect then runs path.Clean, which PROMOTES a
	// backslash into that position: a review measured `/./\evil.test` and
	// `/a/../\evil.test` passing the Go guard and the column CHECK, and coming
	// out of http.Redirect as `Location: /\evil.test`.
	//
	// So the value that is actually sent is the value that is checked. Cleaning
	// here and validating the result closes the gap in the direction that cannot
	// reopen: whatever http.Redirect would do has already been done.
	location := path.Clean(req.ReturnPath)
	if !isSafeReturnPath(location) {
		// Not an error to the caller — they are signed in, and where to land is
		// a preference. Logged, because a stored path that only becomes unsafe
		// after cleaning means the start endpoint let something through.
		s.log.Warn("oidc return path became unsafe after cleaning; redirecting to the root",
			"request_id", requestIDFrom(r.Context()), "stored", truncate(req.ReturnPath, 256))
		location = "/"
	}
	http.Redirect(w, r, location, http.StatusSeeOther)
}

// errIDPUnreachable distinguishes an identity provider outage from its refusal.
//
// The difference decides a status code and a log level, and therefore whether an
// operator finds out that their provider is down.
var errIDPUnreachable = errors.New("api: identity provider unreachable")

// oidcBindingCookieName carries the browser binding between /start and the
// callback.
//
// The __Host- prefix is enforced by the browser: it requires Secure, forbids
// Domain, and requires Path=/. So a cookie by this name cannot have been set by
// a sibling hostname — which on a SaaS deployment is another tenant — and the
// browser refuses to send it over plaintext. That is a property no server-side
// check can obtain, which is why the prefix is used rather than a plain name.
//
// It falls back to an unprefixed name only when Insecure is set, because
// __Host- requires Secure and Insecure exists exactly for the loopback
// development case where there is no TLS. api.New refuses Insecure anywhere but
// loopback.
const (
	oidcBindingCookieSecure   = "__Host-cvap_oidc"
	oidcBindingCookieInsecure = "cvap_oidc"
)

// errBrowserMismatch means the callback came from a different user agent than
// the one that began the flow — or from one that never began a flow at all.
var errBrowserMismatch = errors.New("api: oidc callback browser binding does not match")

// oidcBindingCookie sets the binding.
//
// #nosec G124 -- Secure is set unless Config.Insecure, which api.New refuses
// anywhere but loopback; HttpOnly and SameSite are literal.
func (s *Server) oidcBindingCookie(value string, ttl time.Duration) *http.Cookie {
	return &http.Cookie{
		Name:     s.oidcBindingName(),
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   !s.cfg.Insecure,
		// Lax, not Strict: the callback IS a cross-site top-level navigation —
		// the identity provider redirects into it — so Strict would withhold the
		// cookie on the one request that needs it. Lax sends it on exactly this
		// shape of request, which is why the binding has to be a value the
		// attacker cannot obtain rather than a same-site assertion.
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	}
}

func (s *Server) oidcBindingName() string {
	if s.cfg.Insecure {
		return oidcBindingCookieInsecure
	}
	return oidcBindingCookieSecure
}

// clearOIDCBinding removes the cookie on every callback exit path.
//
// Every path, success and failure alike: a binding left behind is one a second
// callback could present, which would turn a single-use state into a single-use
// state plus a reusable binding.
func (s *Server) clearOIDCBinding(w http.ResponseWriter) {
	http.SetCookie(w, s.expiredCookie(s.oidcBindingName(), true))
}

// errOIDCNoAccount means the assertion was valid and names nobody here.
var errOIDCNoAccount = errors.New("api: no account for this subject")

// resolveOIDCUser maps a verified assertion to a user in this tenant.
//
// Three cases, in the order that makes email the weakest of them:
//
//  1. The subject is already linked. That user, and nothing else is consulted —
//     an email that changed at the IdP does not move the account.
//  2. The subject is new and an unlinked user holds the asserted email. Linked
//     ONCE, and only when the IdP says email_verified. This is the one moment an
//     email identifies a person here, and it is bounded by a conditional UPDATE
//     that cannot relink an account already bound to a different subject.
//  3. Nobody. Refused, unless the tenant turned on auto-provisioning — because
//     otherwise the identity provider decides who has an account in this system,
//     and the role such a user would get is a permission grant made by the IdP.
func (s *Server) resolveOIDCUser(ctx context.Context, c *store.Conn, cfg *store.AuthConfig, subject, email string, emailVerified *bool) (*store.User, error) {
	if subject == "" {
		// errOIDCNoAccount, not a generic error: a hostile identity provider
		// asserting sub:"" would otherwise drive a 500 and an Error-level log
		// line on demand, and produce a status code distinguishable from every
		// other refusal.
		return nil, errOIDCNoAccount
	}

	user, err := (store.Users{}).GetBySubject(ctx, c, cfg.OIDCIssuer, subject)
	switch {
	case err == nil:
		if user.Status != store.UserActive {
			return nil, errOIDCNoAccount
		}
		return user, nil
	case !errors.Is(err, store.ErrNotFound):
		return nil, err
	}

	// Linking by email, once.
	if email != "" && emailVerified != nil && *emailVerified {
		existing, err := (store.Users{}).GetByEmail(ctx, c, email)
		switch {
		case err == nil:
			if existing.Status == store.UserDisabled {
				return nil, errOIDCNoAccount
			}
			if err := (store.Users{}).LinkSubject(ctx, c, existing.ID, cfg.OIDCIssuer, subject); err != nil {
				// ErrNotFound here means the row is already linked to a
				// DIFFERENT subject. The newer assertion does not win.
				if errors.Is(err, store.ErrNotFound) {
					return nil, errOIDCNoAccount
				}
				return nil, err
			}
			// An invited user becomes active by completing a login, which is
			// what an invitation is for.
			if existing.Status == store.UserInvited {
				if err := (store.Users{}).SetStatus(ctx, c, existing.ID, store.UserActive); err != nil {
					return nil, err
				}
				existing.Status = store.UserActive
			}
			return existing, nil
		case !errors.Is(err, store.ErrNotFound):
			return nil, err
		}
	}

	if !cfg.OIDCAutoProvision || cfg.OIDCDefaultRoleID == nil {
		return nil, errOIDCNoAccount
	}
	if email == "" || emailVerified == nil || !*emailVerified {
		// Auto-provisioning without a verified address would create an account
		// nobody can be contacted at and whose identity rests on a claim the
		// provider declined to stand behind.
		return nil, errOIDCNoAccount
	}

	created, err := (store.Users{}).Create(ctx, c, *cfg.OIDCDefaultRoleID, email, "oidc")
	if err != nil {
		return nil, err
	}
	if err := (store.Users{}).LinkSubject(ctx, c, created.ID, cfg.OIDCIssuer, subject); err != nil {
		return nil, err
	}
	if err := (store.Users{}).SetStatus(ctx, c, created.ID, store.UserActive); err != nil {
		return nil, err
	}
	created.Status = store.UserActive
	return created, nil
}

// exchangeCode swaps the authorization code for an ID token.
//
// Done here rather than through golang.org/x/oauth2 so that the request goes
// through the hardened client — the token endpoint comes from an
// operator-supplied issuer's discovery document, so it is the same SSRF surface
// discovery is.
//
// No client secret: the client is public and PKCE is what authenticates the
// exchange (migration 0026 records why there is no secret to store).
func (s *Server) exchangeCode(ctx context.Context, tokenEndpoint, clientID, code, verifier, redirectURI string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("api: building the token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.oidcClient.Do(req)
	if err != nil {
		// Wrapped so the caller can tell an OUTAGE from a refusal. A connection
		// refused, a TLS failure, a timeout and an address the SSRF guard
		// rejected all land here; none of them is the user's doing.
		return "", fmt.Errorf("%w: %w", errIDPUnreachable, err)
	}
	defer resp.Body.Close()

	// Bounded. The body comes from a host named in operator-supplied
	// configuration, and an unbounded read is a way to make Core allocate until
	// it dies.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("api: reading the token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		// The provider's error body is NOT included: it is third-party text on a
		// path that ends in a browser.
		//
		// 5xx is the provider failing, which is an outage; 4xx is it refusing
		// this exchange, which is not.
		if resp.StatusCode >= 500 {
			return "", fmt.Errorf("%w: token endpoint returned %d", errIDPUnreachable, resp.StatusCode)
		}
		return "", fmt.Errorf("api: token endpoint returned %d", resp.StatusCode)
	}

	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("api: token response is not JSON: %w", err)
	}
	if tok.IDToken == "" {
		return "", errors.New("api: token response carried no id_token")
	}
	return tok.IDToken, nil
}

// redirectURI is where the identity provider sends the browser back.
//
// Built from tenants.domain — the value tenant_for_domain matched — rather than
// from the Host header or a request parameter. The Host header is what RESOLVED
// the tenant, so using it here would be circular in a way that mostly works;
// reading the column is the version that cannot be influenced at all.
func (s *Server) redirectURI(ctx context.Context, tenant store.TenantID) (string, error) {
	var domain string
	if err := s.db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		t, err := (store.Tenants{}).Get(ctx, c)
		if err != nil {
			return err
		}
		domain = t.Domain
		return nil
	}); err != nil {
		return "", err
	}
	scheme := "https"
	if s.cfg.Insecure {
		// Only reachable on loopback — New refuses Insecure anywhere else.
		scheme = "http"
	}
	return scheme + "://" + domain + OIDCCallbackPath, nil
}

// OIDCCallbackPath is the one path an identity provider is registered against.
const OIDCCallbackPath = "/v1/auth/oidc/callback"

// isSafeReturnPath rejects everything that is not a path on this site.
//
// The dangerous inputs are not exotic: "//evil.test" is a protocol-relative URL
// that a browser follows off-site, and "/\evil.test" is the same thing after the
// backslash normalisation several browsers perform. Both begin with "/" and both
// pass any check that only looks at the first character.
func isSafeReturnPath(p string) bool {
	if p == "/" {
		return true
	}
	if len(p) < 2 || p[0] != '/' {
		return false
	}
	if p[1] == '/' || p[1] == '\\' {
		return false
	}
	// No scheme, no host, no control characters — a path, a query and a fragment
	// are all this is for.
	if strings.ContainsAny(p, "\r\n\x00") {
		return false
	}
	u, err := url.Parse(p)
	return err == nil && u.Scheme == "" && u.Host == ""
}

// newPKCE returns a verifier and its S256 challenge (RFC 7636).
func newPKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("api: generating a pkce verifier: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// constantTimeEqualHash compares a plaintext value against a stored SHA-256.
func constantTimeEqualHash(plaintext string, want []byte) bool {
	if plaintext == "" || len(want) == 0 {
		return false
	}
	sum := sha256.Sum256([]byte(plaintext))
	return subtle.ConstantTimeCompare(sum[:], want) == 1
}

// addressFromClaims reads the email address and ITS verification claim.
//
// The pair travels together on purpose. `email_verified` is defined as a
// statement about `email`; a deployment that maps the address to `upn` needs
// `upn_verified` to say anything about `upn`, and in its absence the honest
// answer is "not verified" rather than "look at a different claim".
func (s *Server) addressFromClaims(idToken *oidc.IDToken, claim string) (string, *bool, error) {
	if claim == "" || claim == "email" {
		var c struct {
			Email         string `json:"email"`
			EmailVerified *bool  `json:"email_verified"`
		}
		if err := idToken.Claims(&c); err != nil {
			return "", nil, fmt.Errorf("api: id token claims could not be read: %w", err)
		}
		return c.Email, c.EmailVerified, nil
	}

	var raw map[string]any
	if err := idToken.Claims(&raw); err != nil {
		return "", nil, fmt.Errorf("api: id token claims could not be read: %w", err)
	}
	v, ok := raw[claim].(string)
	if !ok || v == "" {
		// REFUSED rather than falling back to `email`. The fallback was the
		// defect: an operator configures a non-default claim because they do not
		// trust the default, and silently using it anyway inverts that decision.
		return "", nil, fmt.Errorf("api: id token carries no %q claim", claim)
	}
	var verified *bool
	if b, ok := raw[claim+"_verified"].(bool); ok {
		verified = &b
	}
	return v, verified, nil
}
