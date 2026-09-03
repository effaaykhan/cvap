package api_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/control/api"
	"github.com/effaaykhan/cvap/internal/store"
)

// oidcFixture is a tenant configured for single sign-on against a fake IdP.
type oidcFixture struct {
	*fixture
	idp *fakeIDP

	// binding is the cookie /start issued, carried to the callback the way a
	// browser carries it.
	binding *http.Cookie
}

func newOIDCFixture(t *testing.T, permissions string, autoProvision bool) *oidcFixture {
	t.Helper()
	f := newFixture(t, permissions)
	idp := newFakeIDP(t)

	// AllowPrivateIssuers, because the fake runs on loopback. That is the same
	// setting an on-prem deployment with an internal identity provider uses, and
	// it is the reason the setting exists rather than a test-only hatch.
	srv, err := api.New(f.db, slog.New(slog.NewJSONHandler(io.Discard, nil)), api.Config{
		Version: "test", LocalAuthEnabled: true, Insecure: true,
		ListenAddr: "127.0.0.1:0", SessionTTL: time.Hour,
		AllowPrivateIssuers: true, OIDCRootCAs: idp.roots(),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.srv = srv

	var roleID uuid.UUID
	if err := f.db.Read(context.Background(), f.tenant, func(ctx context.Context, c *store.Conn) error {
		roles, err := (store.Roles{}).List(ctx, c)
		if err != nil {
			return err
		}
		roleID = roles[0].ID
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	cfg := store.AuthConfig{
		Method: store.AuthOIDC, OIDCIssuer: idp.issuer, OIDCClientID: idp.audience,
		OIDCEmailClaim: "email", OIDCAutoProvision: autoProvision,
	}
	if autoProvision {
		cfg.OIDCDefaultRoleID = &roleID
	}
	if err := f.db.Write(context.Background(), f.tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.AuthConfigs{}).Upsert(ctx, c, cfg, nil)
	}); err != nil {
		t.Fatal(err)
	}
	return &oidcFixture{fixture: f, idp: idp}
}

// start drives the start endpoint and returns the state and nonce the server
// minted, read out of the authorization URL the way a browser would.
//
// It also KEEPS the browser-binding cookie, because a browser would. That is not
// a convenience: the binding is what stops an attacker completing their own
// login and handing the result to a victim, so a test harness that dropped the
// cookie would be testing a flow no browser performs and would have passed
// against the version that had no binding at all.
func (o *oidcFixture) start(t *testing.T, returnTo string) (state, nonce, challenge string) {
	t.Helper()
	path := "/v1/auth/oidc/start"
	if returnTo != "" {
		path += "?return_to=" + url.QueryEscape(returnTo)
	}
	w := o.do(t, http.MethodGet, path, nil, nil, "")
	if w.Code != http.StatusOK {
		t.Fatalf("oidc start gave %d: %s", w.Code, w.Body.String())
	}
	o.binding = nil
	for _, c := range w.Result().Cookies() {
		if c.Name == api.OIDCBindingCookieNameForTest(true) && c.Value != "" {
			o.binding = c
		}
	}
	if o.binding == nil {
		t.Fatal("oidc start set no browser-binding cookie")
	}
	var resp struct {
		AuthorizationURL string `json:"authorization_url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(resp.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	return q.Get("state"), q.Get("nonce"), q.Get("code_challenge")
}

// callback drives the callback endpoint at this fixture's host, presenting the
// binding cookie the way the browser that started the flow would.
func (o *oidcFixture) callback(t *testing.T, state string) *httptest.ResponseRecorder {
	t.Helper()
	var cookies []*http.Cookie
	if o.binding != nil {
		cookies = append(cookies, o.binding)
	}
	return o.do(t, http.MethodGet,
		"/v1/auth/oidc/callback?code=test-code&state="+url.QueryEscape(state), nil, cookies, "")
}

// callbackWithoutBinding is the attacker's request: a URL they assembled,
// arriving in a browser that never called /start.
func (o *oidcFixture) callbackWithoutBinding(t *testing.T, state string) *httptest.ResponseRecorder {
	t.Helper()
	return o.do(t, http.MethodGet,
		"/v1/auth/oidc/callback?code=test-code&state="+url.QueryEscape(state), nil, nil, "")
}

// TestOIDCLoginIssuesTheSameSessionLocalAuthDoes, end to end through a real
// signature, a real JWKS fetch and a real token exchange.
func TestOIDCLoginIssuesTheSameSessionLocalAuthDoes(t *testing.T) {
	o := newOIDCFixture(t, `{"scan.read": true}`, false)

	// Link the existing operator account by verified email on first login.
	o.idp.email = o.email

	state, nonce, challenge := o.start(t, "/scans")
	o.idp.nonce = nonce

	w := o.callback(t, state)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("callback gave %d: %s", w.Code, w.Body.String())
	}
	if loc := w.Header().Get("Location"); loc != "/scans" {
		t.Errorf("redirected to %q, want /scans", loc)
	}

	// PKCE actually travelled, and the verifier matches the challenge the
	// authorization request carried.
	if got := o.idp.lastForm["code_verifier"]; got == "" {
		t.Error("the token exchange sent no code_verifier")
	} else if api.PKCEChallengeForTest(got) != challenge {
		t.Errorf("the verifier sent does not hash to the challenge advertised: %q vs %q",
			api.PKCEChallengeForTest(got), challenge)
	}
	if o.idp.lastForm["grant_type"] != "authorization_code" {
		t.Errorf("grant_type = %q", o.idp.lastForm["grant_type"])
	}
	if o.idp.lastForm["redirect_uri"] == "" {
		t.Error("the token exchange sent no redirect_uri; RFC 6749 requires it to match")
	}

	// The session it minted works, and carries the same permissions local login
	// would have given.
	cookies := w.Result().Cookies()
	var csrf string
	for _, c := range cookies {
		if c.Name == api.CSRFCookie {
			csrf = c.Value
		}
	}
	if got := o.do(t, http.MethodGet, "/v1/scans", nil, cookies, csrf); got.Code != http.StatusOK {
		t.Errorf("the session from an OIDC login does not work: %d %s", got.Code, got.Body.String())
	}

	// And the subject is now linked, so the next login does not depend on email.
	var subject string
	if err := o.db.Read(context.Background(), o.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx,
			`SELECT coalesce(oidc_subject, '') FROM users WHERE tenant_id = $1 AND user_id = $2`,
			o.tenant.UUID(), o.userID).Scan(&subject)
	}); err != nil {
		t.Fatal(err)
	}
	if subject != o.idp.subject {
		t.Errorf("oidc_subject = %q, want %q — a returning user must be identified by subject, "+
			"not by an address the identity provider can reassign", subject, o.idp.subject)
	}
}

// TestAStateFromOneTenantCannotBeRedeemedAtAnother.
//
// ============================================================================
// The property the whole chain from session 10 rests on.
// ============================================================================
//
// The callback is the one endpoint here that takes a third party's redirect, and
// it can name no tenant: the HOST resolves the tenant, and the state is redeemed
// inside that tenant's RLS scope. A state minted at A and replayed at B is a row
// B cannot see.
func TestAStateFromOneTenantCannotBeRedeemedAtAnother(t *testing.T) {
	a := newOIDCFixture(t, `{"scan.read": true}`, false)
	b := newOIDCFixture(t, `{"scan.read": true}`, false)
	a.idp.email = a.email

	state, nonce, _ := a.start(t, "")
	a.idp.nonce = nonce
	b.idp.nonce = nonce
	b.idp.email = a.email

	// Tenant A's state, presented at tenant B's host.
	w := b.callback(t, state)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("tenant A's state was redeemed at tenant B: %d %s", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == api.SessionCookie && c.Value != "" {
			t.Fatal("a session cookie was issued for a cross-tenant state")
		}
	}

	// And it is still redeemable at A, so the refusal above was about the
	// tenant rather than about the state having been consumed.
	if got := a.callback(t, state); got.Code != http.StatusSeeOther {
		t.Errorf("the state stopped working at its own tenant: %d %s", got.Code, got.Body.String())
	}
}

// TestAStateIsSingleUse. Replay is what state exists to stop.
func TestAStateIsSingleUse(t *testing.T) {
	o := newOIDCFixture(t, `{}`, false)
	o.idp.email = o.email

	state, nonce, _ := o.start(t, "")
	o.idp.nonce = nonce

	if w := o.callback(t, state); w.Code != http.StatusSeeOther {
		t.Fatalf("first callback gave %d: %s", w.Code, w.Body.String())
	}
	if w := o.callback(t, state); w.Code != http.StatusUnauthorized {
		t.Errorf("the same state was redeemed twice: %d", w.Code)
	}
}

// TestAnUnknownOrExpiredStateIsRefused.
func TestAnUnknownOrExpiredStateIsRefused(t *testing.T) {
	o := newOIDCFixture(t, `{}`, false)

	if w := o.callback(t, "a-state-nobody-minted"); w.Code != http.StatusUnauthorized {
		t.Errorf("an unknown state gave %d, want 401", w.Code)
	}

	// An already-expired row, inserted directly.
	//
	// Not an UPDATE of a live one: migration 0027 grants SELECT, INSERT and
	// DELETE on this table and deliberately no UPDATE, because the row is never
	// modified — single-use is won by the DELETE ... RETURNING in Consume. A
	// test that needed UPDATE would be a test asking for a grant the design does
	// not want to exist.
	expiredState := "an-expired-state-" + randomHex(t, 8)
	sum := sha256.Sum256([]byte(expiredState))
	if err := o.db.Write(context.Background(), o.tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := c.Exec(ctx, `
			INSERT INTO oidc_auth_requests
				(tenant_id, state_hash, nonce_hash, browser_hash, code_verifier,
				 redirect_uri, created_at, expires_at)
			VALUES ($1, $2, $3, $3, 'v', 'https://x.invalid/cb',
			        now() - interval '1 hour', now() - interval '55 minutes')`,
			o.tenant.UUID(), sum[:], sum[:])
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if w := o.callback(t, expiredState); w.Code != http.StatusUnauthorized {
		t.Errorf("an expired state gave %d, want 401", w.Code)
	}
}

// TestAnExpiredAuthRequestIsNotConsumedByAFailedCallback.
//
// Consume's predicate includes the expiry, so an expired row is not deleted by
// the attempt that failed on it — the sweeper's purge is what removes it. Worth
// asserting because the opposite arrangement, deleting whatever the state
// matched and then checking expiry, would let an attacker delete a victim's
// in-flight login by guessing nothing at all.
func TestAnExpiredAuthRequestIsNotConsumedByAFailedCallback(t *testing.T) {
	o := newOIDCFixture(t, `{}`, false)

	state := "another-expired-state-" + randomHex(t, 8)
	sum := sha256.Sum256([]byte(state))
	if err := o.db.Write(context.Background(), o.tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := c.Exec(ctx, `
			INSERT INTO oidc_auth_requests
				(tenant_id, state_hash, nonce_hash, browser_hash, code_verifier,
				 redirect_uri, created_at, expires_at)
			VALUES ($1, $2, $3, $3, 'v', 'https://x.invalid/cb',
			        now() - interval '1 hour', now() - interval '55 minutes')`,
			o.tenant.UUID(), sum[:], sum[:])
		return err
	}); err != nil {
		t.Fatal(err)
	}

	o.callback(t, state)

	var remaining int
	if err := o.db.Read(context.Background(), o.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx,
			`SELECT count(*) FROM oidc_auth_requests WHERE tenant_id = $1 AND state_hash = $2`,
			o.tenant.UUID(), sum[:]).Scan(&remaining)
	}); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Errorf("the expired row was deleted by the callback that failed on it; Consume must " +
			"match on expiry so a failed attempt cannot remove rows it was never entitled to")
	}
}

// TestTheNonceIsCheckedAgainstThisLoginAttempt.
//
// go-oidc does not check the nonce — it cannot know what was minted — so a
// verifier without this accepts any valid token from the issuer, including one
// obtained for a different login or a different application entirely.
func TestTheNonceIsCheckedAgainstThisLoginAttempt(t *testing.T) {
	o := newOIDCFixture(t, `{}`, false)
	o.idp.email = o.email

	// A token minted for a DIFFERENT login attempt: valid signature, right
	// issuer, right audience, wrong nonce.
	state, _, _ := o.start(t, "")
	_, otherNonce, _ := o.start(t, "")
	o.idp.nonce = otherNonce

	if w := o.callback(t, state); w.Code != http.StatusUnauthorized {
		t.Errorf("a token carrying another attempt's nonce was accepted: %d", w.Code)
	}

	// And no nonce at all is refused too.
	state2, _, _ := o.start(t, "")
	o.idp.nonce = ""
	if w := o.callback(t, state2); w.Code != http.StatusUnauthorized {
		t.Errorf("a token carrying no nonce was accepted: %d", w.Code)
	}
}

// TestTheAudienceIsCheckedAgainstThisTenantsClient.
//
// A token minted for another tenant's client id has a valid signature from an
// issuer this tenant trusts. Accepting it is the cross-tenant hole the host-first
// chain exists to close, reappearing at the last step.
func TestTheAudienceIsCheckedAgainstThisTenantsClient(t *testing.T) {
	o := newOIDCFixture(t, `{}`, false)
	o.idp.email = o.email

	state, nonce, _ := o.start(t, "")
	o.idp.nonce = nonce
	o.idp.audience = "some-other-tenants-client"

	if w := o.callback(t, state); w.Code != http.StatusUnauthorized {
		t.Errorf("a token minted for another client id was accepted: %d", w.Code)
	}
}

// TestTheIssuerIsCheckedAgainstThisTenantsConfiguration.
func TestTheIssuerIsCheckedAgainstThisTenantsConfiguration(t *testing.T) {
	o := newOIDCFixture(t, `{}`, false)
	o.idp.email = o.email

	state, nonce, _ := o.start(t, "")
	o.idp.nonce = nonce
	o.idp.issuer = "https://a-different-issuer.example"

	if w := o.callback(t, state); w.Code != http.StatusUnauthorized {
		t.Errorf("a token claiming a different issuer was accepted: %d", w.Code)
	}
}

// TestASignatureFromTheWrongKeyIsRefused. The JWKS fetch has to be doing
// something, and this is what says so.
func TestASignatureFromTheWrongKeyIsRefused(t *testing.T) {
	o := newOIDCFixture(t, `{}`, false)
	o.idp.email = o.email

	state, nonce, _ := o.start(t, "")
	o.idp.nonce = nonce
	o.idp.signWithWrongKey = true

	if w := o.callback(t, state); w.Code != http.StatusUnauthorized {
		t.Errorf("a token signed with a key not in the JWKS was accepted: %d", w.Code)
	}
}

// TestAnExpiredIDTokenIsRefused.
func TestAnExpiredIDTokenIsRefused(t *testing.T) {
	o := newOIDCFixture(t, `{}`, false)
	o.idp.email = o.email

	state, nonce, _ := o.start(t, "")
	o.idp.nonce = nonce
	o.idp.expiry = time.Now().Add(-time.Minute)

	if w := o.callback(t, state); w.Code != http.StatusUnauthorized {
		t.Errorf("an expired id token was accepted: %d", w.Code)
	}
}

// TestAnUnknownSubjectWithoutAutoProvisioningIsRefused.
//
// The identity provider authenticated somebody. That is not the same as their
// having an account here, and the difference is who decides — an auto-provision
// default means the IdP does.
func TestAnUnknownSubjectWithoutAutoProvisioningIsRefused(t *testing.T) {
	o := newOIDCFixture(t, `{}`, false)
	o.idp.email = "stranger@" + o.domain

	state, nonce, _ := o.start(t, "")
	o.idp.nonce = nonce

	if w := o.callback(t, state); w.Code != http.StatusUnauthorized {
		t.Errorf("an unknown subject was admitted with auto-provisioning off: %d", w.Code)
	}
}

// TestAutoProvisioningCreatesAUserWithTheConfiguredRole, and only with a verified
// address.
func TestAutoProvisioningCreatesAUserWithTheConfiguredRole(t *testing.T) {
	o := newOIDCFixture(t, `{"scan.read": true}`, true)
	o.idp.email = "newcomer@" + o.domain

	// Unverified first: refused, because an auto-provisioned account whose
	// address the provider will not stand behind is an account anybody can claim.
	state, nonce, _ := o.start(t, "")
	o.idp.nonce = nonce
	o.idp.verified = false
	if w := o.callback(t, state); w.Code != http.StatusUnauthorized {
		t.Errorf("an unverified address was auto-provisioned: %d", w.Code)
	}

	state, nonce, _ = o.start(t, "")
	o.idp.nonce = nonce
	o.idp.verified = true
	if w := o.callback(t, state); w.Code != http.StatusSeeOther {
		t.Fatalf("auto-provisioning gave %d: %s", w.Code, w.Body.String())
	}

	var status, provider string
	if err := o.db.Read(context.Background(), o.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx,
			`SELECT status::text, auth_provider FROM users
			  WHERE tenant_id = $1 AND oidc_subject = $2`,
			o.tenant.UUID(), o.idp.subject).Scan(&status, &provider)
	}); err != nil {
		t.Fatal(err)
	}
	if status != "active" || provider != "oidc" {
		t.Errorf("auto-provisioned user is status=%q provider=%q", status, provider)
	}
}

// TestAnUnverifiedEmailDoesNotLinkAnExistingAccount.
//
// The takeover this closes: an identity provider that lets somebody set an
// arbitrary unverified address would otherwise hand them any account here whose
// email they claimed.
func TestAnUnverifiedEmailDoesNotLinkAnExistingAccount(t *testing.T) {
	o := newOIDCFixture(t, `{}`, false)
	o.idp.email = o.email
	o.idp.verified = false

	state, nonce, _ := o.start(t, "")
	o.idp.nonce = nonce

	if w := o.callback(t, state); w.Code != http.StatusUnauthorized {
		t.Errorf("an unverified address linked an existing account: %d", w.Code)
	}
}

// TestASecondSubjectCannotTakeALinkedAccount.
//
// Once an account is bound to a subject, a later assertion carrying the same
// email and a different subject does not win. Otherwise the linking step is a
// takeover primitive that stays open forever rather than closing after one use.
func TestASecondSubjectCannotTakeALinkedAccount(t *testing.T) {
	o := newOIDCFixture(t, `{}`, false)
	o.idp.email = o.email

	state, nonce, _ := o.start(t, "")
	o.idp.nonce = nonce
	if w := o.callback(t, state); w.Code != http.StatusSeeOther {
		t.Fatalf("first login gave %d: %s", w.Code, w.Body.String())
	}

	// Same verified email, different subject.
	o.idp.subject = "a-completely-different-subject"
	state, nonce, _ = o.start(t, "")
	o.idp.nonce = nonce
	if w := o.callback(t, state); w.Code != http.StatusUnauthorized {
		t.Errorf("a second subject took an account already linked to another: %d", w.Code)
	}
}

// TestReturnToMustBeAPathOnThisSite.
//
// An absolute return_to makes the callback an open redirect, which is a phishing
// primitive that borrows this deployment's hostname and its TLS certificate.
// "//evil.test" is the one that matters: it starts with a slash and a browser
// follows it off-site.
func TestReturnToMustBeAPathOnThisSite(t *testing.T) {
	o := newOIDCFixture(t, `{}`, false)

	for _, bad := range []string{
		"https://evil.test/",
		"//evil.test/",
		"/\\evil.test",
		"http://evil.test",
		"javascript:alert(1)",
	} {
		w := o.do(t, http.MethodGet,
			"/v1/auth/oidc/start?return_to="+url.QueryEscape(bad), nil, nil, "")
		if w.Code != http.StatusBadRequest {
			t.Errorf("return_to=%q gave %d, want 400", bad, w.Code)
		}
	}

	for _, good := range []string{"/", "/scans", "/scans?status=running#top"} {
		w := o.do(t, http.MethodGet,
			"/v1/auth/oidc/start?return_to="+url.QueryEscape(good), nil, nil, "")
		if w.Code != http.StatusOK {
			t.Errorf("return_to=%q gave %d, want 200: %s", good, w.Code, w.Body.String())
		}
	}
}

// TestTheRedirectURIComesFromTheTenantsDomain, not from the request.
func TestTheRedirectURIComesFromTheTenantsDomain(t *testing.T) {
	o := newOIDCFixture(t, `{}`, false)
	o.idp.email = o.email

	state, nonce, _ := o.start(t, "")
	o.idp.nonce = nonce
	if w := o.callback(t, state); w.Code != http.StatusSeeOther {
		t.Fatalf("callback gave %d: %s", w.Code, w.Body.String())
	}

	got := o.idp.lastForm["redirect_uri"]
	if !strings.Contains(got, o.domain) || !strings.HasSuffix(got, api.OIDCCallbackPath) {
		t.Errorf("redirect_uri = %q; it must be built from tenants.domain, which is the value "+
			"tenant_for_domain matched and the only one the caller cannot influence", got)
	}
}

// TestATenantOnLocalAuthHasNoOIDCFlow, and vice versa: the method is the
// tenant's row, not a parameter.
func TestATenantOnLocalAuthHasNoOIDCFlow(t *testing.T) {
	f := newFixture(t, `{}`) // local auth, from newFixture
	w := f.do(t, http.MethodGet, "/v1/auth/oidc/start", nil, nil, "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("a local-auth tenant started an OIDC flow: %d %s", w.Code, w.Body.String())
	}
}

// TestOIDCStartLeaksWhetherATenantUsesSingleSignOn, which it does, and this
// test records the fact rather than asserting a property that does not hold.
//
// ============================================================================
// An honest test for a gap the ADR overclaimed.
// ============================================================================
//
// A configured OIDC tenant answers 200; an unknown host and a local-auth tenant
// both answer 401. On a SaaS deployment — where ADR-046 makes single sign-on the
// only login path — that 200-versus-401 answers "does a customer exist at this
// hostname", which is the question the 401/404 fix closed on /v1/auth/login.
//
// It is close to inherent: an endpoint whose job is to hand back an
// authorization URL cannot both do that and be indistinguishable from one that
// refuses. The previous version of this test asserted indistinguishability and
// passed only because its own comment quietly conceded the 200 — which is a test
// documenting a property it is not checking.
//
// So this asserts the two REFUSALS are identical, which is achievable and worth
// keeping, and names the residual leak so nobody has to rediscover it.
func TestOIDCStartLeaksWhetherATenantUsesSingleSignOn(t *testing.T) {
	o := newOIDCFixture(t, `{}`, false)

	// An unknown host and a tenant on local auth: identical refusals.
	local := newFixture(t, `{}`)
	localW := local.do(t, http.MethodGet, "/v1/auth/oidc/start", nil, nil, "")

	r := httptest.NewRequest(http.MethodGet, "/v1/auth/oidc/start", nil)
	r.Host = "nobody-configured-this.test"
	unknownW := httptest.NewRecorder()
	o.srv.Handler().ServeHTTP(unknownW, r)

	if localW.Code != http.StatusUnauthorized || unknownW.Code != http.StatusUnauthorized {
		t.Errorf("a local-auth tenant gave %d and an unknown host %d; both must be 401",
			localW.Code, unknownW.Code)
	}
	if bodyWithoutRequestID(t, localW.Body.Bytes()) != bodyWithoutRequestID(t, unknownW.Body.Bytes()) {
		t.Errorf("the two refusals differ:\n  %s\n  %s", localW.Body.String(), unknownW.Body.String())
	}

	// And the residual: a configured tenant answers 200, which is the leak.
	if w := o.do(t, http.MethodGet, "/v1/auth/oidc/start", nil, nil, ""); w.Code != http.StatusOK {
		t.Fatalf("a configured OIDC tenant gave %d, want 200 — if this ever becomes 401 the "+
			"leak is closed and this test should say so", w.Code)
	}
}

// TestATokenEndpointFailureIsNotReportedToTheBrowser.
//
// The provider's error body is third-party text on a path that ends in a
// browser, and its status is information about someone else's service.
func TestATokenEndpointFailureIsNotReportedToTheBrowser(t *testing.T) {
	o := newOIDCFixture(t, `{}`, false)
	o.idp.email = o.email

	state, nonce, _ := o.start(t, "")
	o.idp.nonce = nonce
	o.idp.tokenStatus = http.StatusBadRequest

	w := o.callback(t, state)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("a failed exchange gave %d, want 401", w.Code)
	}
	if strings.Contains(w.Body.String(), "invalid_grant") {
		t.Errorf("the identity provider's error body reached the browser: %s", w.Body.String())
	}
}

// TestATokenResponseWithoutAnIDTokenIsRefused.
func TestATokenResponseWithoutAnIDTokenIsRefused(t *testing.T) {
	o := newOIDCFixture(t, `{}`, false)
	o.idp.email = o.email

	state, nonce, _ := o.start(t, "")
	o.idp.nonce = nonce
	o.idp.omitIDToken = true

	if w := o.callback(t, state); w.Code != http.StatusUnauthorized {
		t.Errorf("a token response with no id_token was accepted: %d", w.Code)
	}
}

// TestEachLoginWritesExactlyOneAuditEventNamingTheRealMethod.
//
// ============================================================================
// Found by an ADR-compliance pass, and invisible to every test that existed.
// ============================================================================
//
// issueSession hardcoded {"method": "local"} and the OIDC callback recorded its
// own event as well, so every single-sign-on login left TWO rows, one of them
// claiming a local password login had succeeded — on a SaaS tenant, where all
// three conditions for local auth are unsatisfiable. An operator querying the
// audit log for local-auth use got a false positive on every SSO session.
//
// The test asserts on audit_events, not on the response, because every test that
// looked at the response passed against the broken version.
func TestEachLoginWritesExactlyOneAuditEventNamingTheRealMethod(t *testing.T) {
	o := newOIDCFixture(t, `{}`, false)
	o.idp.email = o.email

	state, nonce, _ := o.start(t, "")
	o.idp.nonce = nonce
	if w := o.callback(t, state); w.Code != http.StatusSeeOther {
		t.Fatalf("callback gave %d: %s", w.Code, w.Body.String())
	}

	type row struct {
		method string
		issuer string
	}
	var rows []row
	if err := o.db.Read(context.Background(), o.tenant, func(ctx context.Context, c *store.Conn) error {
		res, err := c.Query(ctx,
			`SELECT detail->>'method', coalesce(detail->>'issuer', '')
			   FROM audit_events
			  WHERE tenant_id = $1 AND action = 'auth.session_issued'`, o.tenant.UUID())
		if err != nil {
			return err
		}
		defer res.Close()
		for res.Next() {
			var r row
			if err := res.Scan(&r.method, &r.issuer); err != nil {
				return err
			}
			rows = append(rows, r)
		}
		return res.Err()
	}); err != nil {
		t.Fatal(err)
	}

	if len(rows) != 1 {
		t.Fatalf("one OIDC login wrote %d auth.session_issued events (%+v); it must write one",
			len(rows), rows)
	}
	if rows[0].method != "oidc" {
		t.Errorf("the event says method=%q. A durable row claiming a local password login on a "+
			"tenant where local auth is unsatisfiable makes the three-condition gate "+
			"unauditable, which is the thing it exists for.", rows[0].method)
	}
	if rows[0].issuer != o.idp.issuer {
		t.Errorf("the event names issuer=%q, want %q", rows[0].issuer, o.idp.issuer)
	}
}

// TestChangingTheIssuerDoesNotHandOverAccounts.
//
// ============================================================================
// The subject namespace belongs to the issuer, and the schema has to say so.
// ============================================================================
//
// `sub` is required to be stable and never reassigned WITHIN AN ISSUER. Stored
// without one, the binding follows a change of tenant_auth_config.oidc_issuer
// into a different namespace — so a subject minted by the new provider that
// happens to collide with an old one takes over that account, and the once-only
// linking control does not apply because the row is found by subject lookup
// rather than by the linking path.
//
// This drives exactly that: link an account at issuer A, point the tenant at
// issuer B, and have B assert the SAME subject string.
func TestChangingTheIssuerDoesNotHandOverAccounts(t *testing.T) {
	o := newOIDCFixture(t, `{}`, false)
	o.idp.email = o.email

	state, nonce, _ := o.start(t, "")
	o.idp.nonce = nonce
	if w := o.callback(t, state); w.Code != http.StatusSeeOther {
		t.Fatalf("first login gave %d: %s", w.Code, w.Body.String())
	}
	linkedSubject := o.idp.subject

	// A second identity provider, asserting the same subject string and a
	// DIFFERENT email — so the linking path cannot rescue it either.
	second := newFakeIDP(t)
	second.subject = linkedSubject
	second.email = "someone-else@" + o.domain
	second.audience = o.idp.audience

	srv, err := api.New(o.db, slog.New(slog.NewJSONHandler(io.Discard, nil)), api.Config{
		Version: "test", LocalAuthEnabled: true, Insecure: true,
		ListenAddr: "127.0.0.1:0", SessionTTL: time.Hour,
		AllowPrivateIssuers: true, OIDCRootCAs: second.roots(),
	})
	if err != nil {
		t.Fatal(err)
	}
	o.srv = srv
	if err := o.db.Write(context.Background(), o.tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.AuthConfigs{}).Upsert(ctx, c, store.AuthConfig{
			Method: store.AuthOIDC, OIDCIssuer: second.issuer,
			OIDCClientID: second.audience, OIDCEmailClaim: "email",
		}, nil)
	}); err != nil {
		t.Fatal(err)
	}
	o.idp = second

	state, nonce, _ = o.start(t, "")
	second.nonce = nonce
	if w := o.callback(t, state); w.Code == http.StatusSeeOther {
		t.Error("a subject minted by a DIFFERENT issuer signed in as the account bound to the " +
			"first one. `sub` is unique only within an issuer, so a binding that does not " +
			"record which issuer minted it follows a configuration change into another " +
			"provider's namespace.")
	}

	// The original binding is untouched: it still names issuer A.
	var issuer string
	if err := o.db.Read(context.Background(), o.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx,
			`SELECT coalesce(oidc_issuer, '') FROM users WHERE tenant_id = $1 AND user_id = $2`,
			o.tenant.UUID(), o.userID).Scan(&issuer)
	}); err != nil {
		t.Fatal(err)
	}
	if issuer == second.issuer {
		t.Error("the existing binding was re-pointed at the new issuer")
	}
}

// TestACallbackFromADifferentBrowserIsRefused.
//
// ============================================================================
// Login CSRF. A security review measured a victim being signed into the
// ATTACKER's account, and no test could see it.
// ============================================================================
//
// The attack: the attacker calls /start from their own client, completes the
// login at their own identity provider, holds the resulting code and state, and
// then causes the victim's browser to open the callback URL. Before the binding,
// the victim's browser was issued a session — for the attacker's account — and
// the operator then worked inside an account the attacker reads at leisure. In
// this product that means scan targets and credential profiles.
//
// SameSite=Lax does not help: the callback is a top-level GET navigation, which
// is exactly what Lax permits. state gives single-use; it says nothing about
// which browser arrived.
//
// The test harness had to change for this: start and callback used to be two
// cookieless requests, so it was structurally incapable of noticing.
func TestACallbackFromADifferentBrowserIsRefused(t *testing.T) {
	o := newOIDCFixture(t, `{"scan.read": true}`, false)
	o.idp.email = o.email

	state, nonce, _ := o.start(t, "")
	o.idp.nonce = nonce

	// The victim's browser: it never called /start, so it holds no binding.
	w := o.callbackWithoutBinding(t, state)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("a callback with no browser binding gave %d, want 401: %s", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == api.SessionCookie && c.Value != "" {
			t.Fatal("a session was issued to a browser that never began the flow")
		}
	}

	// A binding from a DIFFERENT flow is refused too — the value has to be the
	// one minted for this attempt, not merely some valid one.
	other := newOIDCFixture(t, `{}`, false)
	other.start(t, "")
	stolen := *other.binding
	stolen.Name = o.binding.Name
	w = o.do(t, http.MethodGet,
		"/v1/auth/oidc/callback?code=test-code&state="+url.QueryEscape(state),
		nil, []*http.Cookie{&stolen}, "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("a binding from another flow was accepted: %d", w.Code)
	}
}

// TestAMismatchedBindingStillConsumesTheState.
//
// The check is inside the transaction that consumes the row, so a failed binding
// costs the attempt. Two properties, and the second was a defect my own first
// version of the fix had:
//
//  1. Returning an error from the closure ROLLS BACK the DELETE, so the state
//     survived and a second callback with the right cookie succeeded — the same
//     shape as the lockout counter a security review found last session.
//  2. A MISSING cookie and a WRONG one behave identically. An early return on
//     absence left the state unconsumed while a wrong value consumed it, which
//     makes them distinguishable by whether a retry works.
func TestAMismatchedBindingStillConsumesTheState(t *testing.T) {
	o := newOIDCFixture(t, `{}`, false)
	o.idp.email = o.email

	state, nonce, _ := o.start(t, "")
	o.idp.nonce = nonce
	good := o.binding

	if w := o.callbackWithoutBinding(t, state); w.Code != http.StatusUnauthorized {
		t.Fatalf("callback without a binding gave %d", w.Code)
	}
	// Now with the right cookie: the state is already gone.
	o.binding = good
	if w := o.callback(t, state); w.Code != http.StatusUnauthorized {
		t.Errorf("the state survived a failed binding check and was redeemed afterwards: %d", w.Code)
	}
}

// TestTheBindingCookieIsClearedOnEveryExit. A binding left behind is one a
// second callback could present.
func TestTheBindingCookieIsClearedOnEveryExit(t *testing.T) {
	o := newOIDCFixture(t, `{}`, false)
	o.idp.email = o.email

	state, nonce, _ := o.start(t, "")
	o.idp.nonce = nonce
	w := o.callback(t, state)

	var cleared bool
	for _, c := range w.Result().Cookies() {
		if c.Name == api.OIDCBindingCookieNameForTest(true) && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Error("the binding cookie was not cleared after a successful callback")
	}
}

// TestAPlaintextJWKSURIIsRefused.
//
// The scheme check listed authorization_endpoint and token_endpoint and omitted
// jwks_uri, and go-oidc does not check it either — so a discovery document
// naming an http jwks_uri completed a login with the signing keys arriving in
// cleartext. Those keys are the root of every signature check.
func TestAPlaintextJWKSURIIsRefused(t *testing.T) {
	o := newOIDCFixture(t, `{}`, false)
	o.idp.servePlainJWKS()

	w := o.do(t, http.MethodGet, "/v1/auth/oidc/start", nil, nil, "")
	if w.Code != http.StatusBadGateway {
		t.Errorf("a discovery document with an http jwks_uri gave %d, want 502: %s",
			w.Code, w.Body.String())
	}
}

// TestAMappedAddressClaimBringsItsOwnVerification.
//
// email_verified is defined by OIDC Core 5.1 as a statement about `email`. With
// the address mapped to another claim, reading the verification from
// email_verified vouches for a claim it does not describe — a review measured a
// token asserting `email: mallory@… (verified)` alongside `upn: op@…` linking
// the attacker's subject to the operator's account.
func TestAMappedAddressClaimBringsItsOwnVerification(t *testing.T) {
	o := newOIDCFixture(t, `{}`, false)
	if err := o.db.Write(context.Background(), o.tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.AuthConfigs{}).Upsert(ctx, c, store.AuthConfig{
			Method: store.AuthOIDC, OIDCIssuer: o.idp.issuer,
			OIDCClientID: o.idp.audience, OIDCEmailClaim: "upn",
		}, nil)
	}); err != nil {
		t.Fatal(err)
	}

	// email_verified true for a DIFFERENT address, and upn carrying the
	// operator's. The verification must not transfer.
	o.idp.email = "mallory@" + o.domain
	o.idp.verified = true
	o.idp.extraClaims = map[string]any{"upn": o.email}

	state, nonce, _ := o.start(t, "")
	o.idp.nonce = nonce
	if w := o.callback(t, state); w.Code == http.StatusSeeOther {
		t.Error("email_verified vouched for the upn claim, linking the attacker's subject to " +
			"the operator's account. It is defined as a statement about `email`.")
	}

	// And an absent configured claim is a refusal, not a fallback to `email` —
	// the claim the operator overrode precisely because they did not trust it.
	o.idp.extraClaims = nil
	state, nonce, _ = o.start(t, "")
	o.idp.nonce = nonce
	if w := o.callback(t, state); w.Code == http.StatusSeeOther {
		t.Error("a token with no upn claim fell back to email")
	}

	// With upn_verified present and true, it works.
	o.idp.extraClaims = map[string]any{"upn": o.email, "upn_verified": true}
	state, nonce, _ = o.start(t, "")
	o.idp.nonce = nonce
	if w := o.callback(t, state); w.Code != http.StatusSeeOther {
		t.Errorf("a properly verified mapped claim was refused: %d %s", w.Code, w.Body.String())
	}
}

// TestAMultiValuedAudienceRequiresAZP.
//
// OIDC Core 3.1.3.7: a token whose aud names several clients must carry azp
// naming the one it was issued to. go-oidc checks only that ours appears
// somewhere in aud, so without this a token minted for another client at the
// same issuer — on a shared-issuer deployment, another tenant's — is accepted.
func TestAMultiValuedAudienceRequiresAZP(t *testing.T) {
	o := newOIDCFixture(t, `{}`, false)
	o.idp.email = o.email
	o.idp.audiences = []string{"someone-elses-client", o.idp.audience}

	state, nonce, _ := o.start(t, "")
	o.idp.nonce = nonce
	if w := o.callback(t, state); w.Code == http.StatusSeeOther {
		t.Error("a multi-valued audience with no azp was accepted")
	}

	// azp naming someone else is refused.
	o.idp.extraClaims = map[string]any{"azp": "someone-elses-client"}
	state, nonce, _ = o.start(t, "")
	o.idp.nonce = nonce
	if w := o.callback(t, state); w.Code == http.StatusSeeOther {
		t.Error("a token whose azp names another client was accepted")
	}

	// azp naming us is fine.
	o.idp.extraClaims = map[string]any{"azp": o.idp.audience}
	state, nonce, _ = o.start(t, "")
	o.idp.nonce = nonce
	if w := o.callback(t, state); w.Code != http.StatusSeeOther {
		t.Errorf("a correctly-scoped multi-valued audience was refused: %d", w.Code)
	}
}

// TestTheRedirectLocationIsCheckedAfterCleaning.
//
// isSafeReturnPath refuses "/\evil.test" because browsers normalise the
// backslash to "//". http.Redirect then runs path.Clean, which PROMOTES a
// backslash into that position — a review measured "/./\evil.test" passing the
// Go guard and the column CHECK and emerging as "Location: /\evil.test".
func TestTheRedirectLocationIsCheckedAfterCleaning(t *testing.T) {
	for _, returnTo := range []string{`/./\evil.test`, `/a/../\evil.test`, "/scans"} {
		o := newOIDCFixture(t, `{}`, false)
		o.idp.email = o.email

		w := o.do(t, http.MethodGet,
			"/v1/auth/oidc/start?return_to="+url.QueryEscape(returnTo), nil, nil, "")
		if w.Code != http.StatusOK {
			continue // refused at the start endpoint, which is also fine
		}
		for _, c := range w.Result().Cookies() {
			if c.Name == api.OIDCBindingCookieNameForTest(true) {
				o.binding = c
			}
		}
		var resp struct {
			AuthorizationURL string `json:"authorization_url"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(resp.AuthorizationURL)
		if err != nil {
			t.Fatal(err)
		}
		o.idp.nonce = u.Query().Get("nonce")

		cb := o.callback(t, u.Query().Get("state"))
		loc := cb.Header().Get("Location")
		if loc == "" {
			continue
		}
		if strings.HasPrefix(loc, "//") || strings.HasPrefix(loc, `/\`) {
			t.Errorf("return_to=%q produced Location: %q, which a browser follows off-site",
				returnTo, loc)
		}
	}
}

// TestLiveLoginAttemptsAreCapped.
//
// /v1/auth/oidc/start is unauthenticated and writes a row per request. A review
// measured 200 anonymous GETs producing 200 rows, against a purge that clears
// BatchLimit per sweep — so above roughly ten a second it never catches up.
func TestLiveLoginAttemptsAreCapped(t *testing.T) {
	o := newOIDCFixture(t, `{}`, false)

	// Fill to the ceiling directly; driving 1000 real starts is a slow way to
	// assert an arithmetic property.
	if err := o.db.Write(context.Background(), o.tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := c.Exec(ctx, `
			INSERT INTO oidc_auth_requests
				(tenant_id, state_hash, nonce_hash, browser_hash, code_verifier,
				 redirect_uri, expires_at)
			SELECT $1::uuid,
			       sha256(($3 || ':' || g::text)::bytea),
			       sha256(($3 || ':' || g::text)::bytea),
			       sha256(($3 || ':' || g::text)::bytea),
			       'v', 'https://x.invalid/cb', now() + interval '5 minutes'
			  FROM generate_series(1, $2) g`,
			o.tenant.UUID(), store.MaxLiveAuthRequestsPerTenant, o.tenant.String())
		return err
	}); err != nil {
		t.Fatal(err)
	}

	w := o.do(t, http.MethodGet, "/v1/auth/oidc/start", nil, nil, "")
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("start at the ceiling gave %d, want 429. An unauthenticated caller must not be "+
			"able to grow this table without bound.", w.Code)
	}
}

// TestAnEmptySubjectIsRefusedNotAFiveHundred.
//
// A hostile identity provider asserting sub:"" would otherwise drive an
// Error-level log line and a distinguishable status code on demand.
func TestAnEmptySubjectIsRefusedNotAFiveHundred(t *testing.T) {
	o := newOIDCFixture(t, `{}`, false)
	o.idp.email = o.email
	o.idp.subject = ""

	state, nonce, _ := o.start(t, "")
	o.idp.nonce = nonce
	if w := o.callback(t, state); w.Code != http.StatusUnauthorized {
		t.Errorf("an empty subject gave %d, want 401", w.Code)
	}
}
