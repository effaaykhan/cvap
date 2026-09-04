package enginepolicy_test

import (
	"go/build"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ============================================================================
// POLICY: an engine may import only what is on this list.
// ============================================================================
//
// An ALLOWLIST, not a denylist, and the difference is the whole guard.
//
// The first version of this file forbade net, net/http, os/exec and friends. A
// scan-safety audit found six ways past it, and the one that mattered was the
// dullest: a package under internal/engines importing internal/netutil, which
// imports net. build.ImportDir returns a directory's OWN imports, so a denylist
// sees `internal/netutil` — an unremarkable name — and passes. The sabotage test
// that "proved" the guard worked imported net directly, which is the case a
// denylist is good at and not the case anyone would actually write.
//
// The others were the same shape: golang.org/x/net/icmp and github.com/miekg/dns
// are not golang.org/x/sys; `import "C"` reaches socket(2) without naming
// syscall; os.StartProcess spawns nmap without naming os/exec.
//
// An allowlist has none of that surface. Anything not named here fails,
// including a helper package invented to launder an import, and including a
// dependency nobody thought of. The cost is that a legitimate new import needs a
// line here — which is exactly the diff a reviewer should see.
//
// # What this proves and does not prove
//
// It does not prove no packet leaves scope: `make safety` does that in week 8,
// in a network namespace with egress capture. It proves something narrower and
// available on every commit — that there is no code in these packages that could
// send one, and no import through which such code could arrive.

// permitted is what a package under internal/engines may import. Exact match, or
// a prefix followed by "/".
//
// Everything here is inert: it parses, formats, measures time, or generates an
// id. None of it can open a socket, spawn a process, or reach the database.
var permitted = []string{
	// Standard library, the inert subset.
	"bytes", "context", "encoding/base64", "encoding/hex", "encoding/json",
	"errors", "fmt", "io", "math", "math/big", "regexp", "slices", "maps",
	"sort", "strconv", "strings", "sync", "sync/atomic", "time", "unicode",
	"log/slog",

	// First-party, and deliberately narrow. internal/domain is model types;
	// internal/logging is the redacting logger. NOT internal/store — engines
	// have no database access — and NOT internal/control or internal/scanpoint.
	"github.com/effaaykhan/cvap/internal/domain",
	"github.com/effaaykhan/cvap/internal/logging",
	"github.com/effaaykhan/cvap/internal/engines",

	// Third-party.
	"github.com/google/uuid",

	// Test-only. The guard checks test imports too, and a test still needs to
	// be a test.
	"testing",
}

// exceptions is the escape hatch, and it is EMPTY.
//
// The discovery engine will need raw sockets. When that session arrives there
// are two outcomes: someone adds an entry here — deliberately, in a diff a
// reviewer sees, with an ADR explaining why that engine may send packets and how
// ADR-024's ceilings bind it — or someone deletes this file because it is in the
// way. Shaping the guard as a policy with a documented exception path is what
// makes the first outcome likely. A test named TestNoopDoesNotImportNet would
// simply be deleted.
//
// An entry is package path -> import paths that package alone may add.
var exceptions = map[string][]string{
	// ========================================================================
	// The first engine that may put a packet on a wire (ADR-047).
	// ========================================================================
	//
	// ONE import, to the logic package: `net`. Granted because a discovery
	// engine that cannot open a socket is not a discovery engine, and refused
	// for everything else — no os/exec, no syscall, no golang.org/x/net, no
	// os/signal. syscall in particular is the raw-socket path, and this engine
	// does connect scanning and unprivileged ICMP precisely so it stays off
	// this list; SYN and ARP need CAP_NET_RAW, which changes how a scan point
	// is DEPLOYED and is deferred to its own session and its own ADR.
	//
	// What binds it is in ADR-047 and is not restated here beyond the shape:
	// the runtime allocates the rate slice, adaptive means downward only, the
	// engine holds no scope data, and the probe corpus lives in the runtime so
	// that a safe job is handed nothing to send.
	//
	// This is the entry the comment below anticipated. Note what it did NOT
	// become: a widening of `permitted`, which would have granted `net` to every
	// engine including ones not yet written.
	"internal/engines/discovery": {"net"},

	// The engine PROCESS shell, and only the shell — same grant as the no-op
	// engine's, for the same reason. This binary needs os.Stdin and os.Stdout;
	// a package that may import `os` is a package that could import `os/exec`,
	// so keeping the pipes here is what holds the logic package's exception to
	// a single import.
	"cmd/cvap-engine-discovery": {"os", "github.com/effaaykhan/cvap/internal/enginewire"},

	// The engine PROCESS shell, and only the shell.
	//
	// ADR-027 decides that engines are separate processes hosted by the scan
	// point runtime. A process needs its pipes, and os.Stdin/os.Stdout are the
	// only way to reach them in Go — so this exception is forced by that ADR
	// rather than chosen. It is granted to cmd/cvap-engine-noop alone, which
	// holds no engine logic: it reads a job, calls internal/engines/noop, and
	// writes back what that returns. The logic package stays under the full
	// allowlist, which is where the "could not send a packet" property lives.
	//
	// Deliberately NOT granted: os/exec, os/signal, syscall, net. The binary
	// handles no signals precisely so that syscall stays off this list — see
	// the comment in main.go. `os` alone still permits os.StartProcess, which
	// is why it is on notablyForbidden; the mitigation is that this package is
	// a page of I/O a reviewer can read in full, not a place logic accumulates.
	//
	// enginewire is the ADR-027 job contract. It parses JSON over two pipes it
	// did not open and imports nothing that could reach a network.
	"cmd/cvap-engine-noop": {"os", "github.com/effaaykhan/cvap/internal/enginewire"},
}

// notablyForbidden exists only to give a better message for the imports someone
// is most likely to reach for. The allowlist above is what actually decides;
// this turns "not permitted" into "not permitted, and here is why nobody will
// accept a patch adding it".
var notablyForbidden = map[string]string{
	"net":              "engines do not open sockets; the runtime is the send path (ADR-024, ADR-027)",
	"net/http":         "engines do not make requests; targets arrive resolved and pre-authorised",
	"os":               "os.StartProcess spawns a subprocess without naming os/exec",
	"os/exec":          "shelling out escapes the runtime's rate allocation entirely (ADR-027)",
	"syscall":          "the raw-socket path",
	"golang.org/x/sys": "the raw-socket path",
	"golang.org/x/net": "still the network, and not covered by forbidding golang.org/x/sys",
	"C":                "cgo reaches socket(2) without importing anything Go forbids",
	"unsafe":           "//go:linkname reaches unexported runtime and net internals",
	"plugin":           "loads arbitrary code at runtime, defeating any import check",
	"crypto/tls":       "a TLS client is a network client",
	"database/sql":     "engines have no database access (internal/engines/CLAUDE.md)",
}

func TestEnginePackagesImportOnlyPermitted(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}

	// Two roots, because ADR-027's unit is a PROCESS and not a directory. The
	// engine packages live under internal/engines; the main that links one and
	// speaks the job contract will live under cmd/cvap-engine-*, and it is as
	// much engine code as what it links. A guard that stopped at internal/
	// engines would leave the binary that actually runs unguarded.
	roots := []string{filepath.Join(root, "internal", "engines")}
	entries, err := os.ReadDir(filepath.Join(root, "cmd"))
	if err == nil {
		for _, e := range entries {
			if e.IsDir() && strings.HasPrefix(e.Name(), "cvap-engine") {
				roots = append(roots, filepath.Join(root, "cmd", e.Name()))
			}
		}
	}

	var dirs []string
	for _, r := range roots {
		if err := filepath.WalkDir(r, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if strings.Contains(path, "/testdata") {
					return filepath.SkipDir
				}
				dirs = append(dirs, path)
			}
			return nil
		}); err != nil {
			t.Fatalf("walk %s: %v", r, err)
		}
	}

	checked := 0
	for _, dir := range dirs {
		pkg, err := build.ImportDir(dir, 0)
		if err != nil {
			continue // not a package
		}
		checked++

		rel, err := filepath.Rel(root, dir)
		if err != nil {
			t.Fatal(err)
		}
		pkgPath := filepath.ToSlash(rel)

		// Build-tagged files are invisible to a mode-0 build context: they land
		// in IgnoredGoFiles and their imports are never read. A file behind
		// //go:build scanmode could import anything and pass. Rather than
		// enumerate build contexts, refuse the construct: an engine has no
		// reason to have platform- or tag-conditional files, and one that
		// genuinely does should say so here.
		if len(pkg.IgnoredGoFiles) > 0 {
			t.Errorf("%s has build-tagged or otherwise ignored Go files %v. Their imports are "+
				"invisible to this check, so a file behind a build tag could import anything. "+
				"Remove the tag, or extend this guard to iterate build contexts.",
				pkgPath, pkg.IgnoredGoFiles)
		}

		// Test imports are checked too. A test that dials out is still code in
		// this tree that opens a socket, and "only in tests" is how the first
		// exception gets made without anyone deciding to make one.
		imports := append(append([]string{}, pkg.Imports...), pkg.TestImports...)
		imports = append(imports, pkg.XTestImports...)
		sort.Strings(imports)

		for _, imp := range imports {
			if isPermitted(imp) || isException(pkgPath, imp) {
				continue
			}
			msg := "not on the permitted list"
			if why, ok := lookupNotable(imp); ok {
				msg = why
			}
			t.Errorf("%s imports %q: %s.\n"+
				"    An engine may import only what `permitted` names. If this is genuinely "+
				"needed, add it to `exceptions` WITH an ADR — deleting this guard is the other "+
				"way to make the build pass, and it is the wrong one.", pkgPath, imp, msg)
		}
	}

	if checked == 0 {
		t.Fatal("no engine packages found; the guard passed over nothing")
	}
	t.Logf("checked %d package(s); %d permitted imports, %d exception(s)",
		checked, len(permitted), len(exceptions))
}

func isPermitted(imp string) bool {
	for _, p := range permitted {
		if imp == p || strings.HasPrefix(imp, p+"/") {
			return true
		}
	}
	return false
}

// isException matches EXACTLY, unlike isPermitted.
//
// It used to share the prefix rule, so granting "os" also granted os/exec,
// os/signal and everything else under it — while the comment three lines above
// the entry said those were deliberately NOT granted. A scan-safety audit
// dropped a file importing os/exec into cmd/cvap-engine-noop and the guard
// passed. os/exec is the single import this whole guard exists to stop, since
// shelling out escapes the runtime's rate allocation entirely.
//
// An exception names one import. If a package needs a subpackage, it gets its
// own line, which is exactly the diff a reviewer should see.
func isException(pkgPath, imp string) bool {
	for _, a := range exceptions[pkgPath] {
		if imp == a {
			return true
		}
	}
	return false
}

func lookupNotable(imp string) (string, bool) {
	if why, ok := notablyForbidden[imp]; ok {
		return why, true
	}
	for bad, why := range notablyForbidden {
		if strings.HasPrefix(imp, bad+"/") {
			return why, true
		}
	}
	return "", false
}
