package store_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// The design property this file defends:
//
//	No caller outside internal/store can obtain a database connection without a
//	tenant context.
//
// That is not a style preference. Forty RLS policies protect this schema and
// none of them helps against a pooled connection carrying the previous
// request's tenant — the policy then evaluates correctly against the wrong
// tenant and returns another customer's rows, and nothing looks wrong.
//
// The property holds only while pgx types stay inside the package. A single
// exported accessor returning *pgxpool.Pool, a helper returning *pgx.Conn, or
// an exported struct field holding either, and callers can go around Read and
// Write entirely. That is one small, well-intentioned commit away at any time,
// and it would be invisible in review because it looks like a convenience.
//
// So it is a test rather than a comment. This parses the package and fails if a
// connection type appears anywhere in its exported surface.
//
// ADR-032 records the rule and, more usefully, the three leaks that produced it:
// pgx.Rows carrying Conn(), pgx.Batch carrying a caller-supplied callback, and
// this guard's own blind spots. Read it before relaxing anything here.

// Types that hand out a connection, or something a connection can be reached
// from. pgx.Tx is here because Tx.Conn() returns *pgx.Conn — which is also why
// store.Conn holds a named pgx.Tx field rather than embedding one: embedding
// would promote Conn() onto store.Conn and hand out the connection through a
// method nobody wrote.
var forbiddenInExportedAPI = []string{
	"pgxpool.Pool",
	"pgxpool.Conn",
	"pgx.Conn",
	"pgx.Tx",
	"pgconn.PgConn",
	"pgconn.HijackedConn",

	// The subtle ones, and the reason this list is not just the obvious
	// connection types.
	//
	// pgx.Rows carries a Conn() *pgx.Conn method, and pgx.BatchResults.Query()
	// returns a pgx.Rows — so returning either hands a caller the raw connection
	// through an interface method that is invisible at the call site.
	// store.Rows and store.BatchResults exist to be returned instead (rows.go).
	"pgx.Rows",
	"pgx.BatchResults",
	"pgx.Row",

	// pgx.Batch is the same hazard arriving through a PARAMETER. Batch.Queue
	// returns a *pgx.QueuedQuery whose Query(fn func(pgx.Rows) error) stores a
	// caller-supplied callback that pgx later invokes with a live pgx.Rows. A
	// caller-supplied batch is therefore a caller-supplied callback, and that
	// callback is handed the pooled connection. store.Batch (batch.go) discards
	// the QueuedQuery so no callback can be attached.
	//
	// The general rule, worth more than the specific entries: a parameter type
	// that carries a caller-supplied function is as dangerous as a return type
	// that exposes a connection.
	"pgx.Batch",
	"pgx.QueuedQuery",
}

// parsePackage reads every non-test .go file in this directory.
//
// parser.ParseFile per file rather than parser.ParseDir: the latter is
// deprecated as of Go 1.25 because it ignores build tags. That caveat matters
// here — a file excluded by a build tag would still be parsed and could produce
// a spurious failure — but the alternative it points at, go/packages, type-checks
// the world and is far more machinery than a syntactic guard needs. This package
// has no build-tagged files; if one is ever added, this is the thing to revisit.
func parsePackage(t *testing.T) (*token.FileSet, map[string]*ast.File) {
	t.Helper()
	fset := token.NewFileSet()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read internal/store: %v", err)
	}

	files := map[string]*ast.File{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		if f.Name.Name != "store" {
			t.Fatalf("%s declares package %q, expected store", name, f.Name.Name)
		}
		files[name] = f
	}
	if len(files) == 0 {
		t.Fatal("no non-test .go files found; the guards would pass over nothing")
	}
	return fset, files
}

// typeMentions renders a type expression and reports which forbidden type it
// names, if any.
func typeMentions(fset *token.FileSet, expr ast.Expr) string {
	if expr == nil {
		return ""
	}
	var b strings.Builder
	ast.Inspect(expr, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if id, ok := sel.X.(*ast.Ident); ok {
				b.WriteString(id.Name + "." + sel.Sel.Name + " ")
			}
		}
		return true
	})
	rendered := b.String()
	for _, bad := range forbiddenInExportedAPI {
		if strings.Contains(rendered, bad+" ") {
			return bad
		}
	}
	return ""
}

func TestNoConnectionTypeInExportedAPI(t *testing.T) {
	fset, files := parsePackage(t)

	for name, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !fn.Name.IsExported() {
				continue
			}
			// A method on an unexported type is not reachable from outside the
			// package either, but every exported method here is on DB or Conn,
			// so checking all exported funcs is the stricter and simpler rule.
			if fn.Type.Results != nil {
				for _, res := range fn.Type.Results.List {
					if bad := typeMentions(fset, res.Type); bad != "" {
						t.Errorf("%s: exported %s returns %s. "+
							"That hands a caller a connection without a tenant context, "+
							"which is the one failure RLS cannot catch (ADR-002).",
							name, fn.Name.Name, bad)
					}
				}
			}
			if fn.Type.Params != nil {
				for _, p := range fn.Type.Params.List {
					if bad := typeMentions(fset, p.Type); bad != "" {
						t.Errorf("%s: exported %s accepts %s. "+
							"A caller that can supply a connection can supply one with the wrong tenant.",
							name, fn.Name.Name, bad)
					}
				}
			}
		}
	}
}

func TestNoExportedFieldHoldsAConnection(t *testing.T) {
	fset, files := parsePackage(t)

	for name, file := range files {
		ast.Inspect(file, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok || !ts.Name.IsExported() {
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok || st.Fields == nil {
				return true
			}
			for _, f := range st.Fields.List {
				bad := typeMentions(fset, f.Type)
				if bad == "" {
					continue
				}
				// An embedded field has no names, and embedding is the worst
				// case: it promotes the embedded type's methods, so pgx.Tx
				// embedded in Conn would silently export Conn().
				if len(f.Names) == 0 {
					t.Errorf("%s: exported type %s EMBEDS %s, which promotes its methods "+
						"(pgx.Tx.Conn() returns *pgx.Conn). Hold it as a named unexported field instead.",
						name, ts.Name.Name, bad)
					continue
				}
				for _, fieldName := range f.Names {
					if fieldName.IsExported() {
						t.Errorf("%s: exported type %s has exported field %s of type %s. "+
							"Callers can reach the connection directly and skip the tenant context.",
							name, ts.Name.Name, fieldName.Name, bad)
					}
				}
			}
			return true
		})
	}
}

// The three shapes the function-and-struct walk above does not reach.
//
// Each was verified to slip through before this test existed:
//
//	type Escape interface{ Conn() *pgx.Conn }   // interface method
//	type RawPool = pgxpool.Pool                 // alias: TypeSpec, not StructType
//	var Shared *pgxpool.Pool                    // package-level var
//
// The first matters most: rows.go exists because pgx.Rows carries Conn(), and
// without this the guard would not notice store.Rows growing the same method.
func TestNoConnectionTypeInInterfacesAliasesOrVars(t *testing.T) {
	fset, files := parsePackage(t)

	for name, file := range files {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gen.Specs {
				switch sp := spec.(type) {
				case *ast.TypeSpec:
					if !sp.Name.IsExported() {
						continue
					}
					// A type alias exposes the aliased type under a new name.
					if sp.Assign.IsValid() {
						if bad := typeMentions(fset, sp.Type); bad != "" {
							t.Errorf("%s: exported alias %s = %s exposes a connection type.",
								name, sp.Name.Name, bad)
						}
					}
					iface, ok := sp.Type.(*ast.InterfaceType)
					if !ok || iface.Methods == nil {
						continue
					}
					for _, m := range iface.Methods.List {
						ft, ok := m.Type.(*ast.FuncType)
						if !ok {
							// An embedded interface: check the named type itself.
							if bad := typeMentions(fset, m.Type); bad != "" {
								t.Errorf("%s: exported interface %s embeds %s.",
									name, sp.Name.Name, bad)
							}
							continue
						}
						for _, group := range []*ast.FieldList{ft.Results, ft.Params} {
							if group == nil {
								continue
							}
							for _, f := range group.List {
								if bad := typeMentions(fset, f.Type); bad != "" {
									mname := "(embedded)"
									if len(m.Names) > 0 {
										mname = m.Names[0].Name
									}
									t.Errorf("%s: exported interface %s has method %s "+
										"mentioning %s. An interface method is as good as a "+
										"function for handing out a connection.",
										name, sp.Name.Name, mname, bad)
								}
							}
						}
					}
				case *ast.ValueSpec:
					for i, id := range sp.Names {
						if !id.IsExported() {
							continue
						}
						if bad := typeMentions(fset, sp.Type); bad != "" {
							t.Errorf("%s: exported var/const %s is of type %s.",
								name, id.Name, bad)
						}
						if sp.Values != nil && i < len(sp.Values) {
							if bad := typeMentions(fset, sp.Values[i]); bad != "" {
								t.Errorf("%s: exported var/const %s is initialised from %s.",
									name, id.Name, bad)
							}
						}
					}
				}
			}
		}
	}
}

// preTenantMembers is the ADR-033 closed class: the lookups that run BEFORE any
// tenant is known, because deriving the tenant is their whole job.
//
// A third member is an amendment to ADR-033, not an addition to this list — but
// the list is checked, so adding one without reading the ADR fails here with a
// message pointing at it.
var preTenantMembers = map[string]bool{
	"resolvePreTenant":             true, // the shared implementation
	"resolveTenant":                true, // unexported: fingerprint
	"ResolveScanPointTenant":       true, // exported member: fingerprint
	"ResolveEnrollmentTokenTenant": true, // exported member: token hash
}

// Every member of the class returns exactly (TenantID, error) and nothing wider.
//
// Wider is how a lookup becomes a cross-tenant read primitive: returning the
// scan point row, or the token row, would hand a caller data from a tenant whose
// context has not been established. Returning a connection would be worse still
// — it would reopen exactly the hole Read and Write close.
//
// The unexported implementation must stay unexported, and the exported wrappers
// must stay exactly two: they are the only way to reach a SECURITY DEFINER
// function from outside this package.
func TestPreTenantClassStaysNarrow(t *testing.T) {
	fset, files := parsePackage(t)

	seen := map[string]bool{}
	for name, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !preTenantMembers[fn.Name.Name] {
				continue
			}
			seen[fn.Name.Name] = true

			if fn.Type.Results == nil || len(fn.Type.Results.List) != 2 {
				got := 0
				if fn.Type.Results != nil {
					got = len(fn.Type.Results.List)
				}
				t.Errorf("%s: %s returns %d results; every ADR-033 member returns exactly "+
					"(TenantID, error)", name, fn.Name.Name, got)
				continue
			}

			first := fn.Type.Results.List[0].Type
			if id, ok := first.(*ast.Ident); !ok || id.Name != "TenantID" {
				t.Errorf("%s: %s must return TenantID and nothing wider (ADR-033). Returning "+
					"the row turns a pre-tenant lookup into a cross-tenant read primitive.",
					name, fn.Name.Name)
			}
			for _, res := range fn.Type.Results.List {
				if bad := typeMentions(fset, res.Type); bad != "" {
					t.Errorf("%s: %s returns %s. A pre-tenant path that hands back a "+
						"connection has no tenant on it (ADR-033).", name, fn.Name.Name, bad)
				}
			}
		}
	}

	for member := range preTenantMembers {
		if !seen[member] {
			t.Errorf("ADR-033 names %s as a member of the pre-tenant class, but it is not in "+
				"this package. Amend ADR-033 and this list together.", member)
		}
	}
}

// Nothing outside the declared class may query the raw pool.
//
// This is the check that makes "the guard checks the class" true. The test above
// only inspects four names it already knows, so a fifth wrapper —
// ResolveApiKeyTenant, say — would pass it while being exactly the unreviewed
// third member ADR-033 exists to catch.
//
// db.pool is the seam: every pre-tenant lookup reaches it, and everything else
// in the package goes through Read or Write. So any function that touches
// db.pool or calls resolvePreTenant and is not a declared member is either a new
// class member that skipped the ADR, or a query running with no tenant context
// at all.
//
// Open, verifyRole, Close, Ping and inTx are the pool's legitimate lifecycle and
// are listed rather than pattern-matched, so adding one is also a decision.
func TestNothingElseTouchesTheRawPool(t *testing.T) {
	_, files := parsePackage(t)

	poolLifecycle := map[string]bool{
		"Open": true, "verifyRole": true, "Close": true, "Ping": true, "inTx": true,
	}

	for name, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if preTenantMembers[fn.Name.Name] || poolLifecycle[fn.Name.Name] {
				continue
			}

			ast.Inspect(fn.Body, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if sel.Sel.Name == "pool" {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "db" {
						t.Errorf("%s: %s touches db.pool directly. Either it is an undeclared "+
							"member of the ADR-033 pre-tenant class — amend the ADR — or it is a "+
							"query with no tenant context, which Read and Write exist to prevent.",
							name, fn.Name.Name)
					}
				}
				if sel.Sel.Name == "resolvePreTenant" {
					t.Errorf("%s: %s calls resolvePreTenant but is not a declared member of the "+
						"ADR-033 class. Adding a member is an amendment to that ADR.",
						name, fn.Name.Name)
				}
				return true
			})
		}
	}
}

// receiverType returns the bare type name a method hangs off, with any pointer
// and generic decoration stripped: "func (db *DB) Read(...)" gives "DB".
func receiverType(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return ""
	}
	expr := fn.Recv.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if idx, ok := expr.(*ast.IndexExpr); ok {
		expr = idx.X
	}
	if id, ok := expr.(*ast.Ident); ok {
		return id.Name
	}
	return ""
}

// DB must expose no way to start a transaction or acquire a connection other
// than Read and Write. A method called Acquire, Begin, Pool or Conn on DB would
// be that way, whatever it returned.
//
// Scoped to DB rather than to every exported method in the package, because DB
// is the type that holds the pool. Repository methods share some of these names
// legitimately — Submissions.Begin begins a *submission*, not a transaction, and
// banning the word everywhere would push the next author into a worse name for
// the sake of a guard that was aimed at something else.
func TestNoAlternativeEntryPointsOnDB(t *testing.T) {
	_, files := parsePackage(t)

	banned := map[string]string{
		"Acquire": "hands out a connection outside Read/Write",
		"Begin":   "starts a transaction without a tenant",
		"BeginTx": "starts a transaction without a tenant",
		"Pool":    "exposes the pool",
		"Conn":    "exposes a connection",
		"Tx":      "exposes the transaction",
		"Exec":    "runs a query with no tenant context",
		"Query":   "runs a query with no tenant context",
	}

	for name, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !fn.Name.IsExported() {
				continue
			}
			if receiverType(fn) != "DB" {
				continue
			}
			why, isBanned := banned[fn.Name.Name]
			if !isBanned {
				continue
			}
			t.Errorf("%s: exported method DB.%s %s. Read and Write are the only doors, "+
				"and the tenant is what opens them (ADR-002).", name, fn.Name.Name, why)
		}
	}
}

// Conn must not offer a way back to the transaction or connection it wraps.
func TestConnDoesNotUnwrap(t *testing.T) {
	_, files := parsePackage(t)

	banned := map[string]bool{"Tx": true, "Conn": true, "Pool": true, "Raw": true, "Unwrap": true}

	for name, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !fn.Name.IsExported() {
				continue
			}
			if receiverType(fn) != "Conn" {
				continue
			}
			if banned[fn.Name.Name] {
				t.Errorf("%s: Conn.%s unwraps to the underlying transaction or connection. "+
					"Conn exists precisely so that cannot be reached (ADR-002).", name, fn.Name.Name)
			}
		}
	}
}
