package store_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
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

func parsePackage(t *testing.T) (*token.FileSet, map[string]*ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse internal/store: %v", err)
	}
	pkg, ok := pkgs["store"]
	if !ok {
		t.Fatal("package store not found in .")
	}
	return fset, pkg.Files
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

// resolveTenant is the enrolment lookup (ADR-031) and the one path that runs
// without a tenant, because deriving the tenant is its whole job. Two things
// must stay true of it: it is unexported, and it returns only a TenantID.
//
// If it were exported, it would be a way to call a SECURITY DEFINER function
// from outside the package. If it returned a connection, it would be a way to
// obtain one with no tenant — reopening exactly the hole Read and Write close.
func TestResolveTenantStaysNarrow(t *testing.T) {
	fset, files := parsePackage(t)

	found := false
	for name, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if !strings.EqualFold(fn.Name.Name, "resolveTenant") {
				continue
			}
			found = true

			if fn.Name.IsExported() {
				t.Errorf("%s: resolveTenant must stay unexported (ADR-031): it reaches a "+
					"SECURITY DEFINER function and runs with no tenant context.", name)
			}
			if fn.Type.Results == nil || len(fn.Type.Results.List) != 2 {
				t.Fatalf("%s: resolveTenant should return exactly (TenantID, error), got %d results",
					name, len(fn.Type.Results.List))
			}
			first := fn.Type.Results.List[0].Type
			id, ok := first.(*ast.Ident)
			if !ok || id.Name != "TenantID" {
				t.Errorf("%s: resolveTenant must return TenantID and nothing wider (ADR-031). "+
					"Returning the scan point row turns a lookup into a cross-tenant read primitive.", name)
			}
			if bad := typeMentions(fset, first); bad != "" {
				t.Errorf("%s: resolveTenant returns %s. An enrolment path that hands back a "+
					"connection has no tenant on it (ADR-031).", name, bad)
			}
		}
	}
	if !found {
		t.Skip("resolveTenant not present; nothing to constrain")
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
