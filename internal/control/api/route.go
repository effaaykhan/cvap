package api

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// The route registry, and why it is a value rather than a set of annotations.
//
// ============================================================================
// One declaration decides the path, the authorisation and the document.
// ============================================================================
//
// ADR-025 says to buy commodity infrastructure rather than build it, and a
// reader could reasonably ask why this is not swaggo or oapi-codegen. The
// boundary that ADR draws is analysis versus commodity infrastructure, and a
// spec emitter is neither: it is a consistency mechanism for our own contract.
// Annotations are hand-maintained comments that drift from the handler above
// them — the specific failure being avoided is a route whose declared
// permission and enforced permission differ, which an annotation cannot prevent
// because nothing reads it at runtime.
//
// Here the same value is what the mux dispatches on, what the middleware
// enforces, and what the OpenAPI document is emitted from. They cannot disagree
// because there is only one of them.
//
// Do not "simplify" this to annotations later. The registry is small on purpose;
// what it buys is that a route cannot be served with an authorisation the
// document does not state.

// Access says how a route is reached. There is no zero value that means
// "public": Register refuses a route that declares neither, so a new route is
// unreachable until somebody decides what may reach it.
type Access int

const (
	// AccessUndeclared is the zero value and is always a registration error.
	AccessUndeclared Access = iota

	// AccessPublic is reachable without a session. The tenant is still resolved
	// from the request host — that happens before authentication, not after —
	// so a public route is unauthenticated, never untenanted.
	AccessPublic

	// AccessSession requires a valid session and nothing more. For the routes
	// that describe the caller to themselves.
	AccessSession

	// AccessPermission requires a valid session holding Permission.
	AccessPermission
)

// Route is one endpoint.
type Route struct {
	Method  string
	Path    string
	Summary string

	// Description becomes the OpenAPI description. Written for whoever is
	// integrating against this, not for whoever is reading the code.
	Description string

	Access     Access
	Permission Permission

	// Request and Response are zero values of the body types, used to emit the
	// schemas. nil means no body.
	Request  any
	Response any

	// Status is the success status. 0 means 200.
	Status int

	// Handler serves the route. It is referenced ONLY by Server.mount, which is
	// what makes the middleware chain unskippable: there is no other path to it.
	Handler http.HandlerFunc
}

// Mutating reports whether the route changes state. Method-derived: GET and HEAD
// are safe by definition of HTTP, everything else is treated as mutating whether
// or not it happens to be.
func (r Route) Mutating() bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

// Registry holds the routes, and is the only thing that mounts them.
type Registry struct {
	routes []Route
	seen   map[string]bool
}

func NewRegistry() *Registry { return &Registry{seen: map[string]bool{}} }

// Register adds a route, or panics.
//
// Panics rather than returning an error, deliberately: registration happens once
// at startup from a fixed list, so a failure is a programming error that must
// stop the process rather than a condition to handle. A Core that started with
// a route it could not describe would serve an endpoint absent from its own
// document.
func (reg *Registry) Register(r Route) {
	switch {
	case r.Method == "":
		panic("api: route has no method: " + r.Path)
	case !strings.HasPrefix(r.Path, "/"):
		panic("api: route path must be absolute: " + r.Path)
	case r.Handler == nil:
		panic("api: route has no handler: " + r.Method + " " + r.Path)
	case r.Summary == "":
		// Not decoration. The summary is what appears in the generated
		// document, and a route with none produces an entry no integrator can
		// act on.
		panic("api: route has no summary: " + r.Method + " " + r.Path)
	}

	// Deny by default, enforced at registration.
	//
	// This is the check that makes the whole registry worth having: a route
	// added without thinking about who may call it does not quietly become
	// public, it fails to start.
	switch r.Access {
	case AccessUndeclared:
		panic(fmt.Sprintf(
			"api: %s %s declares no Access. Every route says who may reach it — "+
				"AccessPublic, AccessSession, or AccessPermission with a Permission. "+
				"There is no default, because the default would be the wrong one.",
			r.Method, r.Path))
	case AccessPermission:
		if r.Permission == "" {
			panic(fmt.Sprintf("api: %s %s is AccessPermission with no Permission", r.Method, r.Path))
		}
		if !allPermissions[r.Permission] {
			panic(fmt.Sprintf("api: %s %s names unknown permission %q; add it to allPermissions",
				r.Method, r.Path, r.Permission))
		}
	case AccessPublic, AccessSession:
		if r.Permission != "" {
			panic(fmt.Sprintf("api: %s %s names permission %q but its Access does not require one; "+
				"a permission that is not enforced is worse than none, because the document states it",
				r.Method, r.Path, r.Permission))
		}
	}

	key := r.Method + " " + r.Path
	if reg.seen[key] {
		panic("api: duplicate route " + key)
	}
	reg.seen[key] = true
	reg.routes = append(reg.routes, r)
}

// Routes returns the registered routes, sorted by path then method, so the
// emitted document is byte-stable across runs.
func (reg *Registry) Routes() []Route {
	out := make([]Route, len(reg.routes))
	copy(out, reg.routes)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	return out
}
