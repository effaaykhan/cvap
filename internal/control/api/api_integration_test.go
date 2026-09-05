package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/control/api"
	"github.com/effaaykhan/cvap/internal/control/enrollment"
	"github.com/effaaykhan/cvap/internal/store"
)

func testDB(t *testing.T) *store.DB {
	t.Helper()
	url := os.Getenv("CVAP_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CVAP_TEST_DATABASE_URL not set; skipping operator API integration tests")
	}
	db, err := store.Open(context.Background(), store.Config{URL: url})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

// fixture is one tenant with a domain, a role, a user and a password.
type fixture struct {
	db       *store.DB
	srv      *api.Server
	tenant   store.TenantID
	domain   string
	userID   uuid.UUID
	email    string
	password string
	policyID uuid.UUID
	zoneID   uuid.UUID
}

const testPassword = "correct horse battery staple"

// newFixture builds a tenant reachable at its own hostname.
//
// permissions is the role's permission object, verbatim, so a test can grant
// exactly what it means to test and nothing else.
func newFixture(t *testing.T, permissions string) *fixture {
	t.Helper()
	db := testDB(t)
	ctx := context.Background()

	tenant, err := store.NewTenantID(uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	// A domain per test, so tests can run concurrently against one database and
	// so that tenant resolution is being exercised rather than assumed.
	domain := "t" + strings.ReplaceAll(uuid.NewString(), "-", "")[:20] + ".test"

	f := &fixture{db: db, tenant: tenant, domain: domain, email: "op@" + domain, password: testPassword}

	err = db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		if _, err := (store.Tenants{}).Create(ctx, c, "api-"+domain, domain, store.DeploymentOnPrem); err != nil {
			return err
		}
		role, err := (store.Roles{}).Create(ctx, c, "operator", []byte(permissions))
		if err != nil {
			return err
		}
		user, err := (store.Users{}).Create(ctx, c, role.ID, f.email, "local")
		if err != nil {
			return err
		}
		f.userID = user.ID
		if err := (store.Users{}).SetStatus(ctx, c, user.ID, store.UserActive); err != nil {
			return err
		}
		if err := (store.AuthConfigs{}).Upsert(ctx, c, store.AuthConfig{Method: store.AuthLocal}, nil); err != nil {
			return err
		}
		if err := (store.Credentials{}).Set(ctx, c, user.ID, api.HashPasswordForTest(t, testPassword), false); err != nil {
			return err
		}
		z, err := (store.Zones{}).Create(ctx, c, "zone", store.ZoneInternal, 50, "")
		if err != nil {
			return err
		}
		f.zoneID = z.ID
		p, err := (store.Policies{}).Create(ctx, c, store.PolicySpec{
			Name: "policy", SafetyMode: store.SafetySafe,
		})
		if err != nil {
			return err
		}
		f.policyID = p.ID
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	srv, err := api.New(db, slog.New(slog.NewJSONHandler(io.Discard, nil)), api.Config{
		Version: "test", LocalAuthEnabled: true, Insecure: true,
		ListenAddr: "127.0.0.1:0", SessionTTL: time.Hour,
		// The supported protocol window scan-point health reads: "v1" is current.
		ProtocolVersions: enrollment.VersionWindow{Accepted: "v1", MinSupported: "v1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.srv = srv
	return f
}

// do sends a request at this fixture's host.
func (f *fixture) do(t *testing.T, method, path string, body any, cookies []*http.Cookie, csrf string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = httptest.NewRequest(method, path, bytes.NewReader(b))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r.Host = f.domain
	for _, c := range cookies {
		r.AddCookie(c)
	}
	if csrf != "" {
		r.Header.Set(api.CSRFHeader, csrf)
	}
	w := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(w, r)
	return w
}

// login signs in and returns the cookies and the CSRF token.
func (f *fixture) login(t *testing.T) ([]*http.Cookie, string) {
	t.Helper()
	w := f.do(t, http.MethodPost, "/v1/auth/login",
		map[string]string{"email": f.email, "password": f.password}, nil, "")
	if w.Code != http.StatusOK {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return w.Result().Cookies(), resp.CSRFToken
}

// TestTheTenantComesFromTheHostAndNowhereElse.
//
// ============================================================================
// The single most important property in this package.
// ============================================================================
//
// Two tenants, each at its own hostname, each with its own scan. A request that
// carries tenant A's session and asks for tenant B's scan gets 404 — and so does
// one that tries to name tenant B in the body, which is refused outright because
// no schema here has a field for it.
func TestTheTenantComesFromTheHostAndNowhereElse(t *testing.T) {
	a := newFixture(t, `{"scan.create": true, "scan.read": true}`)
	b := newFixture(t, `{"scan.create": true, "scan.read": true}`)

	cookiesA, csrfA := a.login(t)
	cookiesB, csrfB := b.login(t)

	scanB := b.createScan(t, cookiesB, csrfB)

	// A's session, B's scan id, A's host. Under RLS this is a row A cannot see,
	// and "no such row" and "another tenant's row" must be one answer.
	w := a.do(t, http.MethodGet, "/v1/scans/"+scanB, nil, cookiesA, csrfA)
	if w.Code != http.StatusNotFound {
		t.Errorf("reading another tenant's scan gave %d, want 404: %s", w.Code, w.Body.String())
	}

	// A's session sent to B's HOST. The tenant resolves to B, and A's session
	// token does not exist in B's scope, so it is not a session at all.
	r := httptest.NewRequest(http.MethodGet, "/v1/scans/"+scanB, nil)
	r.Host = b.domain
	for _, c := range cookiesA {
		r.AddCookie(c)
	}
	r.Header.Set(api.CSRFHeader, csrfA)
	w2 := httptest.NewRecorder()
	b.srv.Handler().ServeHTTP(w2, r)
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("tenant A's session at tenant B's host gave %d, want 401. A session is scoped "+
			"to the tenant that issued it: %s", w2.Code, w2.Body.String())
	}
}

// TestAnUnknownHostIsIndistinguishableFromABadPassword.
//
// ============================================================================
// An ADR-compliance pass found this as an oracle, and the test asserted it.
// ============================================================================
//
// tenant_for_domain returns the same NULL for unknown, suspended and closed —
// and then the middleware answered 404 while every live tenant's login refusal
// answered 401. On a SaaS deployment with wildcard DNS that walks the customer
// list: post junk credentials at a hostname and read the status code. The
// previous version of this test asserted the 404, which is how the oracle
// survived review.
//
// The assertion now is equality of the whole response with a live tenant's
// refusal, not a status code, because a status code is what was checked before.
func TestAnUnknownHostIsIndistinguishableFromABadPassword(t *testing.T) {
	f := newFixture(t, `{}`)

	// The reference: a configured host, a real account, a wrong password.
	live := f.do(t, http.MethodPost, "/v1/auth/login",
		map[string]string{"email": f.email, "password": "wrong"}, nil, "")

	for _, host := range []string{
		"nobody-configured-this.test",
		"another-unconfigured.test",
	} {
		r := httptest.NewRequest(http.MethodPost, "/v1/auth/login",
			strings.NewReader(`{"email":"x@y.test","password":"z"}`))
		r.Host = host
		w := httptest.NewRecorder()
		f.srv.Handler().ServeHTTP(w, r)

		if w.Code != live.Code {
			t.Errorf("host %q gave %d and a live tenant's bad password gives %d. The difference "+
				"answers 'is there a customer at this hostname' to anyone who asks.",
				host, w.Code, live.Code)
		}
		if bodyWithoutRequestID(t, w.Body.Bytes()) != bodyWithoutRequestID(t, live.Body.Bytes()) {
			t.Errorf("host %q body %s differs from a live tenant's refusal %s",
				host, w.Body.String(), live.Body.String())
		}
	}
}

// TestASuspendedTenantIsIndistinguishableToo. The validity filter is inside
// tenant_for_domain, so suspended and closed produce the same NULL an unknown
// hostname does — and now the same response.
func TestASuspendedTenantIsIndistinguishableToo(t *testing.T) {
	f := newFixture(t, `{}`)
	live := f.do(t, http.MethodPost, "/v1/auth/login",
		map[string]string{"email": f.email, "password": "wrong"}, nil, "")

	if err := f.db.Write(context.Background(), f.tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.Tenants{}).SetStatus(ctx, c, store.TenantSuspended)
	}); err != nil {
		t.Fatal(err)
	}

	w := f.do(t, http.MethodPost, "/v1/auth/login",
		map[string]string{"email": f.email, "password": f.password}, nil, "")

	if w.Code != live.Code {
		t.Errorf("a suspended tenant's login gave %d; a bad password at a live one gives %d",
			w.Code, live.Code)
	}
	if bodyWithoutRequestID(t, w.Body.Bytes()) != bodyWithoutRequestID(t, live.Body.Bytes()) {
		t.Errorf("a suspended tenant's refusal %s differs from a live one's %s",
			w.Body.String(), live.Body.String())
	}
}

// TestAnAuthenticatedRouteAtAnUnknownHostIsA401.
//
// The same property one layer up: a session route at an unconfigured hostname
// must look like a session route with no cookie, not like a missing resource.
func TestAnAuthenticatedRouteAtAnUnknownHostIsA401(t *testing.T) {
	f := newFixture(t, `{"scan.read": true}`)

	r := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)
	r.Host = "nobody-configured-this.test"
	w := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("a session route at an unconfigured host gave %d, want 401", w.Code)
	}
}

// TestACrossOriginLoginIsRefused.
//
// Login is public and therefore has no session to bind a CSRF token to, so the
// cross-origin check is what covers it. Without it a third-party page can log a
// victim's browser into the ATTACKER's account — and in this product that means
// the victim's later scans, kill-switch actions and enrollment tokens land
// there.
func TestACrossOriginLoginIsRefused(t *testing.T) {
	f := newFixture(t, `{}`)

	body, _ := json.Marshal(map[string]string{"email": f.email, "password": testPassword})
	for _, h := range []map[string]string{
		{"Origin": "https://evil.test"},
		{"Sec-Fetch-Site": "cross-site"},
		{"Sec-Fetch-Site": "same-site"}, // a sibling hostname is a different tenant here
	} {
		r := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
		r.Host = f.domain
		for k, v := range h {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		f.srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Errorf("a login with %v gave %d, want 403", h, w.Code)
		}
	}

	// Same-origin, and the absence of both headers, both work: neither is sent
	// by a CLI, and refusing on absence would break every non-browser client
	// while stopping nothing, because a cross-site form post always sends Origin.
	for _, h := range []map[string]string{
		{"Origin": "https://" + f.domain},
		{"Sec-Fetch-Site": "same-origin"},
		{"Sec-Fetch-Site": "none"},
		{},
	} {
		r := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
		r.Host = f.domain
		for k, v := range h {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		f.srv.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Errorf("a login with %v gave %d, want 200: %s", h, w.Code, w.Body.String())
		}
	}
}

// bodyWithoutRequestID strips the one field that legitimately differs between
// two responses.
func bodyWithoutRequestID(t *testing.T, raw []byte) string {
	t.Helper()
	var b api.ErrorBody
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("not an ErrorBody: %s", raw)
	}
	b.RequestID = ""
	out, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// TestPermissionsAreEnforcedPerRoute.
//
// The role holds scan.read and nothing else. Reading is allowed; creating,
// cancelling and choosing a safety mode are each refused, and the safety-mode
// one is the point — a role that may start scans must not be able to escalate
// one to intrusive without holding that permission separately (ADR-021).
func TestPermissionsAreEnforcedPerRoute(t *testing.T) {
	f := newFixture(t, `{"scan.read": true}`)
	cookies, csrf := f.login(t)

	if w := f.do(t, http.MethodGet, "/v1/scans", nil, cookies, csrf); w.Code != http.StatusOK {
		t.Errorf("listing scans with scan.read gave %d: %s", w.Code, w.Body.String())
	}

	body := map[string]any{
		"policy_id": f.policyID.String(), "scan_type": "discovery",
		"targets": []map[string]any{{"type": "cidr", "value": "192.0.2.0/30", "authorization_verified": true}},
	}
	if w := f.do(t, http.MethodPost, "/v1/scans", body, cookies, csrf); w.Code != http.StatusForbidden {
		t.Errorf("creating a scan without scan.create gave %d, want 403: %s", w.Code, w.Body.String())
	}

	id := uuid.NewString()
	if w := f.do(t, http.MethodPost, "/v1/scans/"+id+"/cancel",
		map[string]string{"reason": "x"}, cookies, csrf); w.Code != http.StatusForbidden {
		t.Errorf("cancelling without scan.cancel gave %d, want 403", w.Code)
	}
	if w := f.do(t, http.MethodPut, "/v1/scans/"+id+"/safety-mode",
		map[string]string{"safety_mode": "intrusive"}, cookies, csrf); w.Code != http.StatusForbidden {
		t.Errorf("setting safety mode without scan.safety_mode gave %d, want 403", w.Code)
	}
	if w := f.do(t, http.MethodPost, "/v1/kill",
		map[string]string{"scope": "tenant", "reason": "x"}, cookies, csrf); w.Code != http.StatusForbidden {
		t.Errorf("issuing a kill without kill.issue gave %d, want 403", w.Code)
	}
}

// TestAMutatingRequestNeedsTheCSRFHeader.
func TestAMutatingRequestNeedsTheCSRFHeader(t *testing.T) {
	f := newFixture(t, `{"scan.read": true, "scan.create": true}`)
	cookies, csrf := f.login(t)

	body := map[string]any{
		"policy_id": f.policyID.String(), "scan_type": "discovery",
		"targets": []map[string]any{{"type": "cidr", "value": "192.0.2.0/30", "authorization_verified": true}},
	}

	if w := f.do(t, http.MethodPost, "/v1/scans", body, cookies, ""); w.Code != http.StatusForbidden {
		t.Errorf("a mutating request with no CSRF header gave %d, want 403: %s", w.Code, w.Body.String())
	}
	if w := f.do(t, http.MethodPost, "/v1/scans", body, cookies, "not-the-token"); w.Code != http.StatusForbidden {
		t.Errorf("a mutating request with the wrong CSRF header gave %d, want 403", w.Code)
	}
	// A read is not gated by it: SameSite=Lax already withholds the cookie from
	// cross-site POSTs, and requiring a header on GET would break every link.
	if w := f.do(t, http.MethodGet, "/v1/scans", nil, cookies, ""); w.Code != http.StatusOK {
		t.Errorf("a read with no CSRF header gave %d, want 200", w.Code)
	}
	if w := f.do(t, http.MethodPost, "/v1/scans", body, cookies, csrf); w.Code != http.StatusCreated {
		t.Errorf("a mutating request with the right CSRF header gave %d, want 201: %s", w.Code, w.Body.String())
	}
}

// TestTheSessionCookieIsNotReadableByScript, and carries the attributes a
// bearer credential in a browser needs.
func TestTheSessionCookieIsNotReadableByScript(t *testing.T) {
	f := newFixture(t, `{}`)
	cookies, csrfToken := f.login(t)

	var session, csrf *http.Cookie
	for _, c := range cookies {
		switch c.Name {
		case api.SessionCookie:
			session = c
		case api.CSRFCookie:
			csrf = c
		}
	}
	if session == nil {
		t.Fatal("login issued no session cookie")
	}
	if !session.HttpOnly {
		t.Error("the session cookie is readable by script; an injected script would be able to " +
			"take a working session out of the operator UI")
	}
	if session.SameSite != http.SameSiteLaxMode {
		t.Errorf("session SameSite = %v, want Lax", session.SameSite)
	}
	if session.Domain != "" {
		t.Errorf("the session cookie sets Domain=%q. A host-only cookie is what keeps one "+
			"tenant's session off a sibling hostname; on SaaS, Domain would share it with "+
			"every customer under the registrable domain.", session.Domain)
	}
	if csrf == nil || csrf.HttpOnly {
		t.Error("the CSRF cookie must exist and must be readable, because the page has to echo it")
	}
	if csrf != nil && csrf.Value != csrfToken {
		t.Error("the CSRF cookie and the response body disagree")
	}

	// The session token is NOT in the body. A body value ends up in logs,
	// browser history and error reporters; an HttpOnly cookie does not.
	w := f.do(t, http.MethodPost, "/v1/auth/login",
		map[string]string{"email": f.email, "password": f.password}, nil, "")
	if strings.Contains(w.Body.String(), session.Value) {
		t.Error("the login response body contains the session token")
	}
}

// TestLoginIsOneRefusalForEveryFailure.
//
// Wrong password, unknown address, and an address at another tenant must be one
// response. Anything they distinguish is something an unauthenticated caller
// learns, and "does this address have an account here" is the question
// users.email's per-tenant uniqueness exists to refuse.
func TestLoginIsOneRefusalForEveryFailure(t *testing.T) {
	f := newFixture(t, `{}`)
	other := newFixture(t, `{}`)

	var bodies []string
	for _, creds := range []map[string]string{
		{"email": f.email, "password": "wrong"},
		{"email": "nobody@" + f.domain, "password": testPassword},
		{"email": other.email, "password": testPassword},
	} {
		w := f.do(t, http.MethodPost, "/v1/auth/login", creds, nil, "")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("login refusal gave %d, want 401: %s", w.Code, w.Body.String())
		}
		var b api.ErrorBody
		if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
			t.Fatal(err)
		}
		// The request id differs by design; everything else must not.
		b.RequestID = ""
		out, _ := json.Marshal(b)
		bodies = append(bodies, string(out))
	}
	for i := 1; i < len(bodies); i++ {
		if bodies[i] != bodies[0] {
			t.Errorf("login refusals differ:\n  %s\n  %s\nAn unauthenticated caller must not be "+
				"able to tell a wrong password from an unknown account.", bodies[0], bodies[i])
		}
	}
}

// TestLogoutEndsTheSession, and the session stays in the table.
func TestLogoutEndsTheSession(t *testing.T) {
	f := newFixture(t, `{"scan.read": true}`)
	cookies, csrf := f.login(t)

	if w := f.do(t, http.MethodPost, "/v1/auth/logout", nil, cookies, csrf); w.Code != http.StatusNoContent {
		t.Fatalf("logout gave %d: %s", w.Code, w.Body.String())
	}
	if w := f.do(t, http.MethodGet, "/v1/scans", nil, cookies, csrf); w.Code != http.StatusUnauthorized {
		t.Errorf("a revoked session still works: %d", w.Code)
	}

	var kept int
	if err := f.db.Read(context.Background(), f.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx,
			`SELECT count(*) FROM sessions WHERE tenant_id = $1 AND revoked_at IS NOT NULL`,
			f.tenant.UUID()).Scan(&kept)
	}); err != nil {
		t.Fatal(err)
	}
	if kept != 1 {
		t.Errorf("revoked sessions in the table = %d, want 1. The row is kept so the audit "+
			"trail survives logout — deleting it erases exactly the sessions an investigation "+
			"cares about.", kept)
	}
}

// TestSafetyModeCannotExceedItsPolicy is ADR-021's ceiling, through the wire.
func TestSafetyModeCannotExceedItsPolicy(t *testing.T) {
	f := newFixture(t, `{"scan.create": true, "scan.read": true, "scan.safety_mode": true}`)
	cookies, csrf := f.login(t)
	scanID := f.createScan(t, cookies, csrf)

	// The policy is safe. Asking for intrusive beneath it is refused, and NOT
	// silently downgraded: a caller told it got intrusive when it got safe would
	// report a scan it did not run.
	w := f.do(t, http.MethodPut, "/v1/scans/"+scanID+"/safety-mode",
		map[string]string{"safety_mode": "intrusive"}, cookies, csrf)
	if w.Code != http.StatusConflict {
		t.Errorf("intrusive under a safe policy gave %d, want 409: %s", w.Code, w.Body.String())
	}

	// Safe is always beneath any policy, and it is recorded rather than being a
	// no-op: "no event" would otherwise mean both "nobody chose" and "chose safe".
	w = f.do(t, http.MethodPut, "/v1/scans/"+scanID+"/safety-mode",
		map[string]string{"safety_mode": "safe"}, cookies, csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("selecting safe gave %d: %s", w.Code, w.Body.String())
	}

	var events int
	if err := f.db.Read(context.Background(), f.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx,
			`SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'scan.safety_mode_selected'`,
			f.tenant.UUID()).Scan(&events)
	}); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Errorf("safety mode audit events = %d, want 1", events)
	}
}

// TestCancellingAScanIsAuditedAndRefusedOnceFinished.
//
// This is the path session 8e built and left unreachable. Everything downstream
// of scans.status = 'cancelled' existed; nothing could write it.
func TestCancellingAScanIsAuditedAndRefusedOnceFinished(t *testing.T) {
	f := newFixture(t, `{"scan.create": true, "scan.read": true, "scan.cancel": true}`)
	cookies, csrf := f.login(t)
	scanID := f.createScan(t, cookies, csrf)

	w := f.do(t, http.MethodPost, "/v1/scans/"+scanID+"/cancel",
		map[string]string{"reason": "wrong target list"}, cookies, csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("cancel gave %d: %s", w.Code, w.Body.String())
	}
	var scan struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &scan); err != nil {
		t.Fatal(err)
	}
	if scan.Status != "cancelled" {
		t.Errorf("status after cancel = %q, want cancelled", scan.Status)
	}

	// Cancelling again is a conflict, not a silent success: "cancel" on
	// something already finished did not do what the operator asked.
	w = f.do(t, http.MethodPost, "/v1/scans/"+scanID+"/cancel",
		map[string]string{"reason": "again"}, cookies, csrf)
	if w.Code != http.StatusConflict {
		t.Errorf("cancelling a finished scan gave %d, want 409: %s", w.Code, w.Body.String())
	}

	var reason string
	if err := f.db.Read(context.Background(), f.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx,
			`SELECT detail->>'reason' FROM audit_events
			  WHERE tenant_id = $1 AND action = 'scan.cancelled'`,
			f.tenant.UUID()).Scan(&reason)
	}); err != nil {
		t.Fatal(err)
	}
	if reason != "wrong target list" {
		t.Errorf("the audit event's reason is %q", reason)
	}
}

// TestIssuingAKillSwitchWorksAndIsAudited — ADR-024 control 4's operator lever.
func TestIssuingAKillSwitchWorksAndIsAudited(t *testing.T) {
	f := newFixture(t, `{"kill.issue": true, "kill.resolve": true}`)
	cookies, csrf := f.login(t)

	w := f.do(t, http.MethodPost, "/v1/kill",
		map[string]string{"scope": "tenant", "reason": "customer called"}, cookies, csrf)
	if w.Code != http.StatusCreated {
		t.Fatalf("issuing a kill gave %d: %s", w.Code, w.Body.String())
	}
	var k struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &k); err != nil {
		t.Fatal(err)
	}

	// A tenant-scoped kill carrying a scan id is refused rather than ignored: a
	// caller who sent one believes they issued a narrow kill.
	w = f.do(t, http.MethodPost, "/v1/kill", map[string]any{
		"scope": "tenant", "scan_id": uuid.NewString(), "reason": "x",
	}, cookies, csrf)
	if w.Code != http.StatusBadRequest {
		t.Errorf("a tenant kill with a scan_id gave %d, want 400", w.Code)
	}

	if w := f.do(t, http.MethodPost, "/v1/kill/"+k.ID+"/resolve", nil, cookies, csrf); w.Code != http.StatusNoContent {
		t.Errorf("resolving gave %d: %s", w.Code, w.Body.String())
	}
}

// TestAnEnrollmentTokenIsShownOnceAndStoredHashed.
func TestAnEnrollmentTokenIsShownOnceAndStoredHashed(t *testing.T) {
	f := newFixture(t, `{"scanpoint.enroll": true}`)
	cookies, csrf := f.login(t)

	w := f.do(t, http.MethodPost, "/v1/enrollment-tokens",
		map[string]any{"zone_id": f.zoneID.String(), "description": "lab"}, cookies, csrf)
	if w.Code != http.StatusCreated {
		t.Fatalf("issuing a token gave %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		TokenID string `json:"token_id"`
		Token   string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Token == "" {
		t.Fatal("no token in the response")
	}

	var stored []byte
	if err := f.db.Read(context.Background(), f.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx,
			`SELECT token_hash FROM enrollment_tokens WHERE tenant_id = $1 AND token_id = $2`,
			f.tenant.UUID(), resp.TokenID).Scan(&stored)
	}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte(resp.Token)) {
		t.Error("the token plaintext is in the database")
	}
}

// TestLocalAuthIsRefusedWhenTheDeploymentFlagIsOff.
//
// The tenant is on-prem and configured for local auth. The flag alone denies —
// which is the property that makes it a deployment control rather than a tenant
// preference.
func TestLocalAuthIsRefusedWhenTheDeploymentFlagIsOff(t *testing.T) {
	f := newFixture(t, `{}`)
	off, err := api.New(f.db, slog.New(slog.NewJSONHandler(io.Discard, nil)), api.Config{
		Version: "test", LocalAuthEnabled: false, Insecure: true,
		ListenAddr: "127.0.0.1:0", SessionTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	body, _ := json.Marshal(map[string]string{"email": f.email, "password": f.password})
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/login", bytes.NewReader(body))
	r.Host = f.domain
	w := httptest.NewRecorder()
	off.Handler().ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("login with the deployment flag off gave %d, want 401. tenant_auth_config "+
			"says local and the tenant is onprem; the flag is Core-wide precisely so that a "+
			"tenant cannot enable password login for itself.", w.Code)
	}
}

// TestASaaSTenantCannotUseLocalAuth. The second of the three conditions.
func TestASaaSTenantCannotUseLocalAuth(t *testing.T) {
	f := newFixture(t, `{}`)
	if err := f.db.Write(context.Background(), f.tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := c.Exec(ctx, `UPDATE tenants SET deployment_mode = 'saas' WHERE tenant_id = $1`, f.tenant.UUID())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	w := f.do(t, http.MethodPost, "/v1/auth/login",
		map[string]string{"email": f.email, "password": f.password}, nil, "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("a SaaS tenant logged in locally: %d %s", w.Code, w.Body.String())
	}
}

// TestABodyNamingATenantIsRefused. DisallowUnknownFields is what does it, and
// the case worth naming is exactly this one.
func TestABodyNamingATenantIsRefused(t *testing.T) {
	f := newFixture(t, `{"scan.create": true}`)
	cookies, csrf := f.login(t)

	w := f.do(t, http.MethodPost, "/v1/scans", map[string]any{
		"tenant_id": uuid.NewString(),
		"policy_id": f.policyID.String(), "scan_type": "discovery",
		"targets": []map[string]any{{"type": "cidr", "value": "192.0.2.0/30", "authorization_verified": true}},
	}, cookies, csrf)
	if w.Code != http.StatusBadRequest {
		t.Errorf("a body carrying tenant_id gave %d, want 400. Ignoring it silently is what "+
			"makes a client believe the field had an effect.", w.Code)
	}
}

// TestTheOpenAPIDocumentIsServedPublicly. A client needs it before it can
// authenticate, and it describes the API's shape rather than this tenant.
func TestTheOpenAPIDocumentIsServedPublicly(t *testing.T) {
	f := newFixture(t, `{}`)
	w := f.do(t, http.MethodGet, "/v1/openapi.json", nil, nil, "")
	if w.Code != http.StatusOK {
		t.Fatalf("openapi.json gave %d", w.Code)
	}
	var doc map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	if doc["openapi"] == nil {
		t.Error("no openapi version in the document")
	}
}

// createScan makes a scan and returns its id.
func (f *fixture) createScan(t *testing.T, cookies []*http.Cookie, csrf string) string {
	t.Helper()
	w := f.do(t, http.MethodPost, "/v1/scans", map[string]any{
		"policy_id": f.policyID.String(), "scan_type": "discovery",
		"targets": []map[string]any{{"type": "cidr", "value": "192.0.2.0/30", "authorization_verified": true}},
	}, cookies, csrf)
	if w.Code != http.StatusCreated {
		t.Fatalf("create scan: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp.ID
}

var _ = io.Discard

// TestTheLockoutCounterActuallyCommits.
//
// ============================================================================
// A security review found this with a probe, and the bug was invisible in review.
// ============================================================================
//
// The first version counted the failure inside the same db.Write transaction
// that then returned an error to refuse the login — so the increment rolled back
// with it. failed_attempts was still 0 after fifteen wrong passwords: the
// lockout existed in the schema, in the store and in the handler, and engaged
// never.
//
// The test asserts the counter in the DATABASE, not the response, because every
// response is identical by design and a test that only checked status codes
// would have passed against the broken version.
func TestTheLockoutCounterActuallyCommits(t *testing.T) {
	f := newFixture(t, `{}`)

	for range 3 {
		w := f.do(t, http.MethodPost, "/v1/auth/login",
			map[string]string{"email": f.email, "password": "wrong"}, nil, "")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("wrong password gave %d, want 401", w.Code)
		}
	}

	var attempts int
	if err := f.db.Read(context.Background(), f.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx,
			`SELECT failed_attempts FROM user_credentials WHERE tenant_id = $1 AND user_id = $2`,
			f.tenant.UUID(), f.userID).Scan(&attempts)
	}); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 {
		t.Fatalf("failed_attempts = %d after three wrong passwords, want 3. A counter written "+
			"in a transaction that then rolls back is a lockout that never engages.", attempts)
	}

	// And a correct password clears it, in a transaction that also commits.
	if _, _ = f.login(t); true {
		if err := f.db.Read(context.Background(), f.tenant, func(ctx context.Context, c *store.Conn) error {
			return c.QueryRow(ctx,
				`SELECT failed_attempts FROM user_credentials WHERE tenant_id = $1 AND user_id = $2`,
				f.tenant.UUID(), f.userID).Scan(&attempts)
		}); err != nil {
			t.Fatal(err)
		}
		if attempts != 0 {
			t.Errorf("failed_attempts = %d after a successful login, want 0", attempts)
		}
	}
}

// TestTheLockoutEngagesAtTheThreshold, and a correct password does not open it.
func TestTheLockoutEngagesAtTheThreshold(t *testing.T) {
	f := newFixture(t, `{}`)

	for range store.LockoutThreshold {
		f.do(t, http.MethodPost, "/v1/auth/login",
			map[string]string{"email": f.email, "password": "wrong"}, nil, "")
	}

	w := f.do(t, http.MethodPost, "/v1/auth/login",
		map[string]string{"email": f.email, "password": testPassword}, nil, "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("the correct password was accepted while the account is locked: %d", w.Code)
	}

	var locked *time.Time
	if err := f.db.Read(context.Background(), f.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx,
			`SELECT locked_until FROM user_credentials WHERE tenant_id = $1 AND user_id = $2`,
			f.tenant.UUID(), f.userID).Scan(&locked)
	}); err != nil {
		t.Fatal(err)
	}
	if locked == nil || !locked.After(time.Now()) {
		t.Errorf("locked_until = %v after %d failures; the lockout did not engage",
			locked, store.LockoutThreshold)
	}
}

// TestLoginDoesNotHoldADatabaseConnectionWhileHashing.
//
// ============================================================================
// The second thing the review's probe found, and the more serious of the two.
// ============================================================================
//
// argon2id at 64 MiB takes tens of milliseconds. Done inside db.Write it held a
// pooled connection for that whole time, so concurrent UNAUTHENTICATED login
// attempts exhausted the pool: an unrelated authenticated read went from 1.8ms
// to 1.1 seconds. A denial of service against the whole deployment, reachable by
// anyone who can post to the login endpoint.
//
// The assertion is on the unrelated read's latency under load, because that is
// the property — not "logins are fast", which they are not and need not be.
func TestLoginDoesNotHoldADatabaseConnectionWhileHashing(t *testing.T) {
	f := newFixture(t, `{"scan.read": true}`)
	cookies, csrf := f.login(t)

	// Baseline: an authenticated read with nothing else happening.
	start := time.Now()
	if w := f.do(t, http.MethodGet, "/v1/scans", nil, cookies, csrf); w.Code != http.StatusOK {
		t.Fatalf("baseline read gave %d", w.Code)
	}
	baseline := time.Since(start)

	// Load: unauthenticated login attempts, each of which performs a full
	// argon2id verification.
	const attackers = 24
	done := make(chan struct{})
	stop := make(chan struct{})
	for range attackers {
		go func() {
			defer func() { done <- struct{}{} }()
			for {
				select {
				case <-stop:
					return
				default:
				}
				f.doQuiet(http.MethodPost, "/v1/auth/login",
					map[string]string{"email": f.email, "password": "wrong"})
			}
		}()
	}

	var worst time.Duration
	for range 5 {
		start = time.Now()
		f.do(t, http.MethodGet, "/v1/scans", nil, cookies, csrf)
		if d := time.Since(start); d > worst {
			worst = d
		}
	}
	close(stop)
	for range attackers {
		<-done
	}

	// TWO conditions, both required, and the reason is that the first version of
	// this bound was an absolute 250ms tuned on a four-core developer machine —
	// which failed in CI at 325ms against a 12.9ms baseline, on a two-core
	// runner under -race where everything is an order of magnitude slower and
	// maxConcurrentHashes is 1.
	//
	// The property is not "this is fast". It is "an unauthenticated endpoint does
	// not starve an authenticated one by orders of magnitude", and that has to be
	// asked relative to the machine. The broken version produced 1.1s against a
	// 1.8ms baseline — 600x — and the CI number that provoked this rewrite was
	// 25x, which is what a busy two-core box looks like rather than what a
	// starved pool looks like.
	//
	// A floor as well as a ratio, because a very fast baseline makes a small
	// absolute delay look enormous.
	const (
		floor = 500 * time.Millisecond
		ratio = 30
	)
	if worst > floor && worst > ratio*baseline {
		t.Errorf("under %d unauthenticated login attempts an unrelated authenticated read took "+
			"%v — %.0fx the %v baseline. The password hash is holding a pooled connection, so "+
			"anyone who can reach the login endpoint can starve the deployment.",
			attackers, worst, float64(worst)/float64(baseline), baseline)
	}
}

// TestAnUnknownAddressCostsTheSameAsAKnownOne.
//
// The third probe finding. Without the decoy verification, an unknown address
// returned in microseconds and a known one took fifty milliseconds — a
// user-enumeration oracle that does not care what the response body says, and
// one that survives every effort to make the bodies identical.
//
// The margin is wide because timing in a test process is noisy. What it catches
// is the shape that matters: one path hashing and the other not.
func TestAnUnknownAddressCostsTheSameAsAKnownOne(t *testing.T) {
	f := newFixture(t, `{}`)

	measure := func(email string) time.Duration {
		var total time.Duration
		const n = 3
		for range n {
			start := time.Now()
			f.do(t, http.MethodPost, "/v1/auth/login",
				map[string]string{"email": email, "password": "wrong"}, nil, "")
			total += time.Since(start)
		}
		return total / n
	}

	known := measure(f.email)
	unknown := measure("nobody@" + f.domain)

	// The unknown path must not be dramatically cheaper. A factor of four is far
	// beyond scheduler noise and far below the 1000x the broken version showed.
	if known > 4*unknown {
		t.Errorf("a known address took %v and an unknown one %v. The gap is the argon2 "+
			"verification happening on one path and not the other, which enumerates users "+
			"regardless of what the response body says.", known, unknown)
	}
}

// doQuiet is do() without the *testing.T, for use from a goroutine.
func (f *fixture) doQuiet(method, path string, body any) {
	b, err := json.Marshal(body)
	if err != nil {
		return
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	r.Host = f.domain
	f.srv.Handler().ServeHTTP(httptest.NewRecorder(), r)
}

// TestInsecureCookiesAreRefusedOnANonLoopbackAddress.
//
// The Config comment used to promise this guard and nothing implemented it — a
// security review found the sentence describing a check that did not exist,
// which is the class of defect this codebase polices everywhere else. The test
// exists so the sentence and the code cannot part company again.
func TestInsecureCookiesAreRefusedOnANonLoopbackAddress(t *testing.T) {
	db := testDB(t)
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))

	for _, addr := range []string{"0.0.0.0:8445", "10.0.0.5:8445", "cvap.corp.example:443", ""} {
		if _, err := api.New(db, log, api.Config{
			Version: "test", Insecure: true, ListenAddr: addr, SessionTTL: time.Hour,
		}); err == nil {
			t.Errorf("insecure cookies were accepted on %q. A session cookie without Secure is "+
				"a bearer credential a browser will send over cleartext.", addr)
		}
	}

	for _, addr := range []string{"127.0.0.1:8445", "[::1]:8445", "localhost:8445"} {
		if _, err := api.New(db, log, api.Config{
			Version: "test", Insecure: true, ListenAddr: addr, SessionTTL: time.Hour,
		}); err != nil {
			t.Errorf("insecure cookies were refused on loopback %q: %v", addr, err)
		}
	}

	// And a secure deployment does not care about the address.
	if _, err := api.New(db, log, api.Config{
		Version: "test", ListenAddr: "0.0.0.0:8445", SessionTTL: time.Hour,
	}); err != nil {
		t.Errorf("a secure configuration was refused: %v", err)
	}
}

// TestAURLScopeRuleIsStoredAsItsHost.
//
// ============================================================================
// Found by an ADR-compliance pass as a new fail-open path this session opened.
// ============================================================================
//
// Since ADR-044 the target side is one bare host and the rule side is stored as
// written. A deny rule saved as "https://printer.corp.example/setup" therefore
// compared against "printer.corp.example" and matched nothing — so an operator
// who excluded a printer got an exclusion that protected it from nothing, and a
// scan that proceeded. ADR-040 already says scope authorises hosts; this is
// where the storage was made to agree.
func TestAURLScopeRuleIsStoredAsItsHost(t *testing.T) {
	f := newFixture(t, `{"policy.write": true, "policy.read": true}`)
	cookies, csrf := f.login(t)

	w := f.do(t, http.MethodPost, "/v1/policies/"+f.policyID.String()+"/scope-rules",
		map[string]any{
			"effect": "deny", "match_type": "url",
			"match_value": "https://printer.corp.example/setup?reset=1",
		}, cookies, csrf)
	if w.Code != http.StatusCreated {
		t.Fatalf("adding a url rule gave %d: %s", w.Code, w.Body.String())
	}
	var rule struct {
		MatchValue string `json:"match_value"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &rule); err != nil {
		t.Fatal(err)
	}
	if rule.MatchValue != "printer.corp.example" {
		t.Errorf("a url rule was stored as %q. The matcher compares against a canonical host, "+
			"so anything else is an exclusion that protects nothing.", rule.MatchValue)
	}
}

// TestATagScopeRuleIsRefused.
//
// The enum accepts tag and dispatch treats it as fatal: scopePlan cannot express
// one on the wire, so a single tag rule refuses EVERY job under that policy,
// permanently. Failing closed at dispatch is right; accepting it here with a 201
// is what would make it silent.
func TestATagScopeRuleIsRefused(t *testing.T) {
	f := newFixture(t, `{"policy.write": true}`)
	cookies, csrf := f.login(t)

	w := f.do(t, http.MethodPost, "/v1/policies/"+f.policyID.String()+"/scope-rules",
		map[string]any{"effect": "deny", "match_type": "tag", "match_value": "pci"},
		cookies, csrf)
	if w.Code != http.StatusBadRequest {
		t.Errorf("a tag rule gave %d, want 400. One of them bricks every job under the policy.", w.Code)
	}
}

// TestAMalformedCidrRuleIsRefused, for the same reason: scopePlan refuses the
// job at dispatch, which is invisible until scans stop running.
func TestAMalformedCidrRuleIsRefused(t *testing.T) {
	f := newFixture(t, `{"policy.write": true}`)
	cookies, csrf := f.login(t)

	for _, v := range []string{"192.0.2.5", "not-a-prefix", "192.0.2.0/33"} {
		w := f.do(t, http.MethodPost, "/v1/policies/"+f.policyID.String()+"/scope-rules",
			map[string]any{"effect": "allow", "match_type": "cidr", "match_value": v},
			cookies, csrf)
		if w.Code != http.StatusBadRequest {
			t.Errorf("a cidr rule of %q gave %d, want 400", v, w.Code)
		}
	}
}

// TestEveryResponseCarriesTheSecurityHeaders asserts the class-of-response
// headers on BOTH a JSON response and the static SPA path.
//
// The static path is the load-bearing case: session 19 shipped the SPA serving
// through spa.go, which does not call writeJSON, and the headers used to live in
// writeJSON — so the operator console (the one origin that executes JS and
// renders scan-target-derived data) was served with none of them. The headers
// moved to a mux-wrapping middleware; this proves the static path inherits them,
// so a header set in the write helper can never again be the whole story. GET /
// is exercised under the default build (the not-built placeholder), which is
// enough — the middleware runs regardless of the embedui tag.
func TestEveryResponseCarriesTheSecurityHeaders(t *testing.T) {
	f := newFixture(t, `{"scan.read": true}`)
	cookies, csrf := f.login(t)

	// The class every path must carry, wherever it is served from.
	theClass := func(t *testing.T, w *httptest.ResponseRecorder, where string) {
		t.Helper()
		for header, want := range map[string]string{
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options":        "DENY",
			"Referrer-Policy":        "no-referrer",
			"Content-Security-Policy": "default-src 'self'; base-uri 'self'; " +
				"frame-ancestors 'none'; object-src 'none'",
		} {
			if got := w.Header().Get(header); got != want {
				t.Errorf("%s: %s = %q, want %q", where, header, got, want)
			}
		}
		if w.Header().Get("Strict-Transport-Security") == "" {
			t.Errorf("%s: no Strict-Transport-Security; the session cookie is a bearer "+
				"credential and the first plaintext request is the one that leaks it", where)
		}
	}

	// The JSON API path (writeJSON), which also carries its own no-store.
	wj := f.do(t, http.MethodGet, "/v1/scans", nil, cookies, csrf)
	theClass(t, wj, "GET /v1/scans")
	if got := wj.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("GET /v1/scans: Cache-Control = %q, want no-store", got)
	}

	// The static SPA path (spa.go), which does NOT call writeJSON — the case the
	// per-write helper could not cover. Public route, so no session needed. The
	// status differs by build (200 with the UI embedded, 503 for the not-built
	// placeholder under the default build this test runs), but the middleware
	// stamps the header class before the handler writes either — which is exactly
	// the property under test, so both statuses are acceptable and neither may be
	// a 404 (the route must exist).
	ws := f.do(t, http.MethodGet, "/", nil, nil, "")
	if ws.Code != http.StatusOK && ws.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET / gave %d, want 200 (embedded UI) or 503 (not-built placeholder)", ws.Code)
	}
	theClass(t, ws, "GET /")
}

// TestALockedAccountIsA401AndNotA500.
func TestALockedAccountIsA401AndNotA500(t *testing.T) {
	f := newFixture(t, `{}`)
	cookies, csrf := f.login(t)

	for range store.LockoutThreshold {
		f.do(t, http.MethodPost, "/v1/auth/password",
			map[string]string{"current_password": "wrong", "new_password": "a-long-enough-one"},
			cookies, csrf)
	}

	w := f.do(t, http.MethodPost, "/v1/auth/password",
		map[string]string{"current_password": testPassword, "new_password": "a-long-enough-one"},
		cookies, csrf)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("a locked account changing its password gave %d, want 401. Reporting a client "+
			"condition as a 500 tells an operator their deployment is broken.", w.Code)
	}
}

// TestALocalLoginIsAuditedAsLocal, the other half of the pair.
func TestALocalLoginIsAuditedAsLocal(t *testing.T) {
	f := newFixture(t, `{}`)
	f.login(t)

	var method string
	var n int
	if err := f.db.Read(context.Background(), f.tenant, func(ctx context.Context, c *store.Conn) error {
		if err := c.QueryRow(ctx,
			`SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'auth.session_issued'`,
			f.tenant.UUID()).Scan(&n); err != nil {
			return err
		}
		return c.QueryRow(ctx,
			`SELECT detail->>'method' FROM audit_events
			  WHERE tenant_id = $1 AND action = 'auth.session_issued'`,
			f.tenant.UUID()).Scan(&method)
	}); err != nil {
		t.Fatal(err)
	}
	if n != 1 || method != "local" {
		t.Errorf("a local login wrote %d events with method=%q; want 1 and \"local\"", n, method)
	}
}
