package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testRegistry(t *testing.T) *Registry {
	t.Helper()
	s := &Server{log: slog.New(slog.NewJSONHandler(io.Discard, nil)), reg: NewRegistry()}
	s.routes()
	return s.reg
}

// TestEveryRouteDeclaresWhoMayReachIt is the deny-by-default property.
//
// It is the reason the registry exists. A route added without deciding who may
// call it must not quietly become public — and the check that stops it is at
// registration, which means the failure is a process that will not start rather
// than an endpoint nobody noticed.
//
// This test asserts the property over the real route table. The registration
// panic is asserted separately below, because a table that happens to be correct
// today proves nothing about the mechanism.
func TestEveryRouteDeclaresWhoMayReachIt(t *testing.T) {
	for _, r := range testRegistry(t).Routes() {
		switch r.Access {
		case AccessUndeclared:
			t.Errorf("%s %s declares no Access", r.Method, r.Path)
		case AccessPermission:
			if !allPermissions[r.Permission] {
				t.Errorf("%s %s names permission %q, which is not in the closed set",
					r.Method, r.Path, r.Permission)
			}
		case AccessPublic:
			// Every public route is listed here BY NAME. A new one has to be
			// added to this list deliberately, which is the review this test
			// exists to force: an endpoint reachable without a session is the
			// most consequential thing anyone can add to this package.
			switch r.Method + " " + r.Path {
			case "POST /v1/auth/login", "GET /v1/openapi.json":
			default:
				t.Errorf("%s %s is public and is not one of the routes this test knows about. "+
					"If that is deliberate, add it here — and say why in the route's Description.",
					r.Method, r.Path)
			}
		}
	}
}

// TestRegistrationRefusesAnUndeclaredRoute drives the mechanism rather than the
// table. A future route table that is entirely correct would still pass the test
// above with this check deleted.
func TestRegistrationRefusesAnUndeclaredRoute(t *testing.T) {
	for _, tc := range []struct {
		name  string
		route Route
	}{
		{
			name: "no Access at all",
			route: Route{Method: http.MethodGet, Path: "/v1/x", Summary: "x",
				Handler: func(http.ResponseWriter, *http.Request) {}},
		},
		{
			name: "AccessPermission with no permission",
			route: Route{Method: http.MethodGet, Path: "/v1/x", Summary: "x",
				Access: AccessPermission, Handler: func(http.ResponseWriter, *http.Request) {}},
		},
		{
			name: "a permission outside the closed set",
			route: Route{Method: http.MethodGet, Path: "/v1/x", Summary: "x",
				Access: AccessPermission, Permission: "scan.everything",
				Handler: func(http.ResponseWriter, *http.Request) {}},
		},
		{
			// The subtle one: a route that STATES a permission the middleware
			// will not enforce, because its Access does not ask for one. The
			// document would say the caller needs it and nothing would check.
			name: "a permission on a session-only route",
			route: Route{Method: http.MethodGet, Path: "/v1/x", Summary: "x",
				Access: AccessSession, Permission: PermScanRead,
				Handler: func(http.ResponseWriter, *http.Request) {}},
		},
		{
			name: "no summary, so the document would have an unusable entry",
			route: Route{Method: http.MethodGet, Path: "/v1/x",
				Access: AccessPublic, Handler: func(http.ResponseWriter, *http.Request) {}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("Register accepted a route it must refuse")
				}
			}()
			NewRegistry().Register(tc.route)
		})
	}
}

// TestMutatingIsDerivedFromTheMethod. A declared flag can be wrong;
// http.MethodGet cannot.
func TestMutatingIsDerivedFromTheMethod(t *testing.T) {
	for method, want := range map[string]bool{
		http.MethodGet: false, http.MethodHead: false, http.MethodOptions: false,
		http.MethodPost: true, http.MethodPut: true, http.MethodPatch: true,
		http.MethodDelete: true,
	} {
		if got := (Route{Method: method}).Mutating(); got != want {
			t.Errorf("%s mutating = %v, want %v", method, got, want)
		}
	}
}

// TestNoRouteAcceptsATenant is the invariant ADR-041 rests on.
//
// The tenant is resolved from the request host, server-side, before any handler
// runs. A request body or query parameter that named one would be a tenant a
// client can choose — so no request type in this package may have a field that
// looks like one, and the generated document must not describe one either.
func TestNoRouteAcceptsATenant(t *testing.T) {
	doc, err := testRegistry(t).OpenAPI("test")
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatalf("the emitted document is not JSON: %v", err)
	}

	for _, bad := range []string{`"tenant_id"`, `"tenantId"`, `"tenant"`} {
		if strings.Contains(string(doc), bad) {
			t.Errorf("the API document mentions %s as a field or parameter. The tenant comes "+
				"from the request host and is never read from a request (ADR-041); a schema "+
				"carrying one is a schema a client will fill in.", bad)
		}
	}
}

// TestTheDocumentDescribesEveryRoute, with its permission.
//
// An integrator reads this document to find out what their account needs to
// hold. A route whose permission is enforced but not described sends them to
// support; one described but not enforced is worse.
func TestTheDocumentDescribesEveryRoute(t *testing.T) {
	reg := testRegistry(t)
	doc, err := reg.OpenAPI("test")
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	var parsed struct {
		Paths map[string]map[string]struct {
			Summary    string `json:"summary"`
			Permission string `json:"x-cvap-permission"`
			Security   []map[string][]string
		} `json:"paths"`
	}
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, r := range reg.Routes() {
		op, ok := parsed.Paths[r.Path][strings.ToLower(r.Method)]
		if !ok {
			t.Errorf("%s %s is served and is not in the document", r.Method, r.Path)
			continue
		}
		if op.Permission != string(r.Permission) {
			t.Errorf("%s %s enforces %q and the document says %q",
				r.Method, r.Path, r.Permission, op.Permission)
		}
		if (r.Access != AccessPublic) != (len(op.Security) > 0) {
			t.Errorf("%s %s: Access is %v and the document's security is %v",
				r.Method, r.Path, r.Access, op.Security)
		}
	}
}

// TestTheDocumentIsStable. It is regenerated on every request, and a document
// whose key order moved between two identical requests would produce a diff in
// every client's vendored copy for no reason.
func TestTheDocumentIsStable(t *testing.T) {
	reg := testRegistry(t)
	a, err := reg.OpenAPI("test")
	if err != nil {
		t.Fatal(err)
	}
	b, err := reg.OpenAPI("test")
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Error("two renders of the same registry differ")
	}
}

// TestErrorBodiesNeverCarrySchemaDetail.
//
// internal/store/CLAUDE.md: mapError embeds ConstraintName, ColumnName and
// Message, every one of which is a schema fact, and the API layer must not
// return them. This drives the real writer with an error that carries all three.
func TestErrorBodiesNeverCarrySchemaDetail(t *testing.T) {
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/v1/scans", nil)

	cause := &fakeStoreError{"store: conflict: constraint findings_dedup_key_uidx, column dedup_key: duplicate key value"}
	writeError(w, r, log, http.StatusConflict, CodeConflict, "That resource already exists.", cause)

	body := w.Body.String()
	for _, leak := range []string{"findings_dedup_key_uidx", "dedup_key", "duplicate key"} {
		if strings.Contains(body, leak) {
			t.Errorf("the response body contains %q, which describes the schema to whoever sent "+
				"the request. The detail belongs in the log against the request id.\nbody: %s",
				leak, body)
		}
	}

	var parsed ErrorBody
	if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("the error body is not an ErrorBody: %v", err)
	}
	if parsed.Error != CodeConflict {
		t.Errorf("code = %q, want %q", parsed.Error, CodeConflict)
	}
}

type fakeStoreError struct{ s string }

func (e *fakeStoreError) Error() string { return e.s }

// TestPermissionsAreAPermissionList is ADR-037 applied to RBAC.
//
// Empty means DENY. The column defaults to '{}', so a role nobody has configured
// grants nothing — which is the opposite of how the ADR treats allowed_zones and
// time_windows, and the reason the distinction is worth a test rather than a
// comment.
func TestPermissionsAreAPermissionList(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want bool
	}{
		{"the column default", `{}`, false},
		{"absent", ``, false},
		{"explicitly false", `{"scan.read": false}`, false},
		{"granted", `{"scan.read": true}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set, err := ParsePermissions([]byte(tc.raw))
			if err != nil {
				t.Fatalf("ParsePermissions: %v", err)
			}
			if got := set.Has(PermScanRead); got != tc.want {
				t.Errorf("Has(scan.read) = %v, want %v", got, tc.want)
			}
		})
	}

	// Malformed is an error, not an empty set. Both deny; only one is visible.
	if _, err := ParsePermissions([]byte(`["scan.read"]`)); err == nil {
		t.Error("a JSON array parsed as a permission set; it must be an object of name to bool, " +
			"and a malformed value must be reported rather than silently denying")
	}
}

// TestThereIsNoPermissionHierarchy. scan.cancel does not follow from
// scan.create: stopping other people's scans is not the same authority as
// starting your own.
func TestThereIsNoPermissionHierarchy(t *testing.T) {
	set, err := ParsePermissions([]byte(`{"scan.create": true}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range PermissionNames() {
		if p == PermScanCreate {
			continue
		}
		if set.Has(p) {
			t.Errorf("a role holding only scan.create also holds %s", p)
		}
	}
}
