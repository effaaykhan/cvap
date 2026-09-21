package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/store"
)

// The budget's operator-facing half (ADR-101, B50).

func newTimeoutTestServer() *Server {
	return &Server{
		log:      slog.New(slog.NewJSONHandler(io.Discard, nil)),
		timeouts: newTimeoutMeter(),
	}
}

// tenantCtx gives a request the context the middleware chain would have given
// it: a tenant and a request id. The id matters — withRequestID is the OUTERMOST
// middleware (server.go), so every handler that can emit an error runs with one,
// and a test that omits it is asserting against a request shape production never
// produces.
func tenantCtx(t *testing.T, r *http.Request) (*http.Request, store.TenantID) {
	t.Helper()
	tenant, err := store.NewTenantID(uuid.New())
	if err != nil {
		t.Fatalf("tenant id: %v", err)
	}
	ctx := context.WithValue(r.Context(), ctxTenant, tenant)
	ctx = context.WithValue(ctx, ctxRequestID, "s44-test-request-id")
	// A session, so the meter counts this as an AUTHENTICATED request. Without
	// one it lands in the anonymous bucket, which is the whole point of
	// TestAnAnonymousCallerCannotMoveTheOperatorsNumber below.
	ctx = context.WithValue(ctx, ctxSession, &store.Session{})
	return r.WithContext(ctx), tenant
}

// anonCtx is the same request with no session: what an unauthenticated caller
// reaches on login or an OIDC callback.
func anonCtx(t *testing.T, r *http.Request) (*http.Request, store.TenantID) {
	t.Helper()
	tenant, err := store.NewTenantID(uuid.New())
	if err != nil {
		t.Fatalf("tenant id: %v", err)
	}
	ctx := context.WithValue(r.Context(), ctxTenant, tenant)
	ctx = context.WithValue(ctx, ctxRequestID, "s44-test-anon")
	return r.WithContext(ctx), tenant
}

// A budget timeout is a 504 with a request id, under its own code.
//
// Not a 500: the request was well formed and the server simply did not finish
// it. Not CodeInternal either — an alert that cannot tell a bug from a query
// that needs profiling pages the wrong person.
func TestABudgetTimeoutIsA504WithARequestID(t *testing.T) {
	s := newTimeoutTestServer()
	w := httptest.NewRecorder()
	r, _ := tenantCtx(t, httptest.NewRequest(http.MethodGet, "/v1/findings", nil))

	s.storeError(w, r, fmt.Errorf("listing findings: %w", store.ErrStatementTimeout))

	if w.Code != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusGatewayTimeout)
	}
	var body ErrorBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("not an ErrorBody: %v", err)
	}
	if body.Error != CodeTimeout {
		t.Errorf("code = %q, want %q", body.Error, CodeTimeout)
	}
	// The request id is the only handle joining this response to the log line
	// that names the statement. A 504 without one is a dead end.
	if body.RequestID != "s44-test-request-id" {
		t.Errorf("request id = %q; without it the operator has nothing to "+
			"correlate the 504 with the log line naming the statement", body.RequestID)
	}
	// The budget is not a retry hint.
	if body.Message == "" {
		t.Error("no message")
	}
}

// The discrimination that keeps the 504 meaningful.
//
// SQLSTATE 57014 is both our bound firing and a client-side cancel, and
// context.Canceled is the caller having left. A caller who went away must not
// be reported as the server running out of budget: it would inflate the one
// number on Health that is supposed to mean "a plan nobody measured".
func TestACancelledCallerIsNotABudgetTimeout(t *testing.T) {
	s := newTimeoutTestServer()
	w := httptest.NewRecorder()
	r, tenant := tenantCtx(t, httptest.NewRequest(http.MethodGet, "/v1/findings", nil))

	s.storeError(w, r, fmt.Errorf("listing findings: %w", context.Canceled))

	if w.Code == http.StatusGatewayTimeout {
		t.Fatal("a cancelled caller was reported as a budget timeout")
	}
	if n, _, _ := s.timeouts.read(tenant); n != 0 {
		t.Fatalf("a cancelled caller was metered as a timeout: count = %d", n)
	}
}

// The meter is per tenant, and that is a tenancy property, not a detail.
//
// Every other number on HealthResponse is tenant-scoped by an RLS-protected
// query. This one lives in memory, so it has to earn the same property in Go —
// otherwise tenant A's Health reports that tenant B is running something slow.
func TestTheTimeoutMeterDoesNotLeakAcrossTenants(t *testing.T) {
	s := newTimeoutTestServer()

	w := httptest.NewRecorder()
	r, noisy := tenantCtx(t, httptest.NewRequest(http.MethodGet, "/v1/findings", nil))
	for i := 0; i < 3; i++ {
		s.storeError(w, r, fmt.Errorf("slow: %w", store.ErrStatementTimeout))
	}

	quiet, err := store.NewTenantID(uuid.New())
	if err != nil {
		t.Fatalf("tenant id: %v", err)
	}

	if n, last, _ := s.timeouts.read(noisy); n != 3 || last == nil {
		t.Fatalf("noisy tenant: count = %d, last = %v; want 3 and a timestamp", n, last)
	}
	if n, last, _ := s.timeouts.read(quiet); n != 0 || last != nil {
		t.Fatalf("a tenant that timed out NOTHING sees count = %d, last = %v — "+
			"that is another tenant's activity showing through Health", n, last)
	}
}

// A timeout response must not describe the schema, like every other error body.
func TestATimeoutBodyCarriesNoSchemaDetail(t *testing.T) {
	s := newTimeoutTestServer()
	w := httptest.NewRecorder()
	r, _ := tenantCtx(t, httptest.NewRequest(http.MethodGet, "/v1/findings", nil))

	s.storeError(w, r, fmt.Errorf(
		"%w: canceling statement due to statement timeout on findings_dedup_key_uidx",
		store.ErrStatementTimeout))

	if body := w.Body.String(); contains(body, "findings_dedup_key_uidx") {
		t.Errorf("the 504 body names a constraint: %s", body)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

// The classification that turned a database timeout into "your password is
// wrong".
//
// isInfrastructureError enumerates the sentinels it treats as FAULTS and
// defaults to "refusal". ErrStatementTimeout did not exist when it was written,
// so login phase 1 answered a budget timeout with 401 "Those credentials are
// not valid." — the exact outcome the comment four lines above that branch
// forbids. An ADR-compliance review measured it; nothing in the suite did,
// because the tests drove the mapping function and never this discriminator.
//
// Kept as a table so the next sentinel added to the store has an obvious place
// to be classified, rather than silently defaulting to a refusal.
func TestABudgetTimeoutIsAFaultNotACredentialRefusal(t *testing.T) {
	if !isInfrastructureError(store.ErrStatementTimeout) {
		t.Fatal("a budget timeout classifies as a REFUSAL, so login answers it " +
			"401 'Those credentials are not valid.' — an outage hidden behind a " +
			"message telling the operator to check their password")
	}
	// The control: the refusal side must stay a refusal, or this test passes by
	// making everything a fault.
	for _, e := range []error{store.ErrNotFound, store.ErrCredentialLocked, store.ErrSessionInvalid} {
		if isInfrastructureError(e) {
			t.Errorf("%v classifies as a fault; it is an authentication outcome", e)
		}
	}
}

// internalError is the flat-500 path that the login and OIDC surfaces use
// instead of storeError, because storeError's 404 would be a user-existence
// oracle there. It must still let the budget through as a 504.
func TestInternalErrorLetsTheBudgetThroughAndNothingElse(t *testing.T) {
	t.Run("a timeout becomes 504", func(t *testing.T) {
		s := newTimeoutTestServer()
		w := httptest.NewRecorder()
		r, tenant := tenantCtx(t, httptest.NewRequest(http.MethodGet, "/v1/auth/session", nil))

		s.internalError(w, r, fmt.Errorf("touch: %w", store.ErrStatementTimeout))

		if w.Code != http.StatusGatewayTimeout {
			t.Fatalf("status = %d, want 504", w.Code)
		}
		if n, _, _ := s.timeouts.read(tenant); n != 1 {
			t.Errorf("not metered on Health: count = %d", n)
		}
	})

	t.Run("a not-found stays an opaque 500", func(t *testing.T) {
		s := newTimeoutTestServer()
		w := httptest.NewRecorder()
		r, _ := tenantCtx(t, httptest.NewRequest(http.MethodGet, "/v1/auth/session", nil))

		s.internalError(w, r, fmt.Errorf("lookup: %w", store.ErrNotFound))

		// 404 here would answer whether the subject exists. The whole reason
		// these call sites avoid storeError is that they must not.
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500 — a 404 on this surface is a "+
				"user-existence oracle", w.Code)
		}
	})
}

// An anonymous caller must not be able to move the number an operator reads to
// decide which query needs profiling.
//
// Measured by a security review before this split existed: an unauthenticated
// login request drove a tenant's timed_out_requests from 0 to 1, repeatable
// without limit, and poisoned last_timeout_at with it. The signal is still
// kept — it is real load — but in its own bucket, documented as attacker-
// influenceable (ADR-102).
func TestAnAnonymousCallerCannotMoveTheOperatorsNumber(t *testing.T) {
	s := newTimeoutTestServer()
	w := httptest.NewRecorder()
	r, tenant := anonCtx(t, httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil))

	for i := 0; i < 5; i++ {
		s.storeError(w, r, fmt.Errorf("slow: %w", store.ErrStatementTimeout))
	}

	n, last, anon := s.timeouts.read(tenant)
	if n != 0 || last != nil {
		t.Errorf("an unauthenticated caller moved the operator-facing count to %d "+
			"(last=%v); that number decides what a human investigates", n, last)
	}
	if anon != 5 {
		t.Errorf("anonymous timeouts = %d, want 5 — the load signal must not be "+
			"thrown away either", anon)
	}
}

// Out of connections is not a slow query, and must not be reported as one.
//
// Measured: with another tenant holding the only pooled connection, this
// tenant's `SELECT 1` came back as ErrStatementTimeout — a 504 telling the
// operator to profile `SELECT 1`, metered against the victim rather than the
// tenant whose load caused it (ADR-102).
func TestPoolExhaustionIs503AndNotMeteredAsAQueryTimeout(t *testing.T) {
	s := newTimeoutTestServer()
	w := httptest.NewRecorder()
	r, tenant := tenantCtx(t, httptest.NewRequest(http.MethodGet, "/v1/assets", nil))

	s.storeError(w, r, fmt.Errorf("acquire: %w", store.ErrPoolExhausted))

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 — capacity is not a query to profile", w.Code)
	}
	var body ErrorBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("not an ErrorBody: %v", err)
	}
	if body.Error != CodeCapacity {
		t.Errorf("code = %q, want %q", body.Error, CodeCapacity)
	}
	if n, _, anon := s.timeouts.read(tenant); n != 0 || anon != 0 {
		t.Errorf("pool exhaustion was metered as a query timeout (n=%d anon=%d): "+
			"it would tell the operator to profile a statement that never ran", n, anon)
	}
}

// The login surface answers ONE status for every fault, whichever phase it came
// from.
//
// This is the property C1 broke: phase 3 is reachable only for an account that
// EXISTS (refuse() returns first for an unknown one), so a distinct status from
// that phase is a clean user-existence positive — and a free one, since the
// rolled-back transaction leaves failed_attempts unmoved and writes no audit
// row. Asserted structurally, because the differential lives in which BRANCH
// answers, not in any single branch.
func TestTheLoginHandlerNeverAnswersAFaultWithADistinctStatus(t *testing.T) {
	src, err := os.ReadFile("handlers_auth.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	fn := string(src)
	start := strings.Index(fn, "func (s *Server) login(")
	if start < 0 {
		t.Fatal("login handler not found")
	}
	end := strings.Index(fn[start:], "\nfunc ")
	if end < 0 {
		end = len(fn) - start
	}
	body := fn[start : start+end]

	// storeError is the only way a status other than the flat 500 reaches the
	// client from a store fault: it maps ErrNotFound to 404 (a user-existence
	// oracle), ErrStatementTimeout to 504 and ErrPoolExhausted to 503.
	if strings.Contains(body, "s.storeError(") {
		t.Error("login calls storeError, so a fault's status now depends on WHICH " +
			"fault it was — on a surface where phase 3 is reachable only for an " +
			"account that exists, that is a user-existence oracle (ADR-102)")
	}
	if !strings.Contains(body, "s.noteTimeout(") {
		t.Error("login no longer meters budget timeouts; the operator loses the " +
			"signal that the bound is firing on the auth path")
	}
}
