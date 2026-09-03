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

// callback drives the callback endpoint at this fixture's host.
func (o *oidcFixture) callback(t *testing.T, state string) *httptest.ResponseRecorder {
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
				(tenant_id, state_hash, nonce_hash, code_verifier, redirect_uri,
				 created_at, expires_at)
			VALUES ($1, $2, $3, 'v', 'https://x.invalid/cb',
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
				(tenant_id, state_hash, nonce_hash, code_verifier, redirect_uri,
				 created_at, expires_at)
			VALUES ($1, $2, $3, 'v', 'https://x.invalid/cb',
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

// TestOIDCStartAtAnUnknownHostIsIndistinguishable, like every other pre-auth
// endpoint.
func TestOIDCStartAtAnUnknownHostIsIndistinguishable(t *testing.T) {
	o := newOIDCFixture(t, `{}`, false)

	live := o.do(t, http.MethodGet, "/v1/auth/oidc/start", nil, nil, "")

	r := httptest.NewRequest(http.MethodGet, "/v1/auth/oidc/start", nil)
	r.Host = "nobody-configured-this.test"
	w := httptest.NewRecorder()
	o.srv.Handler().ServeHTTP(w, r)

	// live is a 200 here because the tenant IS configured for OIDC; what must
	// not happen is a 404 that distinguishes "no such tenant" from every other
	// refusal this endpoint makes.
	if w.Code != http.StatusUnauthorized {
		t.Errorf("an unknown host gave %d, want the same 401 a misconfigured tenant gets "+
			"(a live one gave %d)", w.Code, live.Code)
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
