package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
	if n, _ := s.timeouts.read(tenant); n != 0 {
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

	if n, last := s.timeouts.read(noisy); n != 3 || last == nil {
		t.Fatalf("noisy tenant: count = %d, last = %v; want 3 and a timestamp", n, last)
	}
	if n, last := s.timeouts.read(quiet); n != 0 || last != nil {
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
