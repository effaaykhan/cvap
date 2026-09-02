package engines_test

import (
	"go/build"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ============================================================================
// POLICY: no package under internal/engines imports the network or the shell.
// ============================================================================
//
// Written as a policy with an allowlist rather than as an assertion about the
// engines that happen to exist today, and the difference is the whole point.
//
// The discovery engine will need raw sockets. When that session arrives there
// are two possible outcomes: someone adds an entry to the allowlist below —
// deliberately, in a diff a reviewer sees, with an ADR explaining why that
// engine may send packets and how ADR-024's ceilings bind it — or someone
// deletes this file because it is in the way. Shaping the guard as a policy with
// a documented exception path is what makes the first outcome the likely one. A
// test named TestNoopDoesNotImportNet would simply be deleted.
//
// What this does and does not prove. It does NOT prove no packet leaves scope —
// that is `make safety` in week 8, which runs scans in a network namespace with
// egress capture. It proves something cheaper and available now: that there is
// no code in these packages that could send one. A guard that runs on every
// commit and answers a smaller question is worth more than one that answers the
// whole question and does not exist yet.

// forbidden is what an engine may not reach.
//
// net and net/http are the obvious ones. os/exec matters just as much: an engine
// that shells out to nmap has all the blast radius of one that opens sockets and
// none of the rate limiting, and it would defeat ADR-027's allocation model
// entirely — the runtime cannot allocate a rate slice to a subprocess it does
// not mediate. syscall and golang.org/x/sys are the raw-socket path.
var forbidden = map[string]string{
	"net":                  "engines do not open sockets; the runtime is the send path (ADR-024, ADR-027)",
	"net/http":             "engines do not make requests; targets arrive resolved and pre-authorised",
	"net/url":              "URL construction implies an engine deciding what to reach",
	"os/exec":              "shelling out escapes the runtime's rate allocation entirely (ADR-027)",
	"syscall":              "the raw-socket path",
	"golang.org/x/sys":     "the raw-socket path",
	"crypto/tls":           "a TLS client is a network client",
	"database/sql":         "engines have no database access (internal/engines/CLAUDE.md)",
	"github.com/jackc/pgx": "engines have no database access",
}

// allowed is the exception list. EMPTY TODAY, and adding to it is a decision.
//
// An entry here says: this package may reach this thing, for this reason, and
// somebody thought about ADR-024's ceilings when they wrote it down. The
// discovery engine is the expected first entry, and it should arrive with an ADR
// rather than as a line in this map.
var allowed = map[string][]string{
	// "internal/engines/discovery": {"net", "syscall"},  // ADR-0xx, when it lands
}

// Packages the engines may reach without argument: they carry no capability to
// send anything.
var neutralPrefixes = []string{
	"context", "encoding/", "errors", "fmt", "time", "sort", "strings", "strconv",
	"bytes", "io", "math", "sync", "unicode", "slices", "maps", "log/slog",
	"github.com/google/uuid",
	"github.com/effaaykhan/cvap/internal/domain",
	"github.com/effaaykhan/cvap/internal/logging",
}

func TestEnginesImportNoNetworkOrShell(t *testing.T) {
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	enginesDir := filepath.Join(root, "engines")

	var packages []string
	err = filepath.WalkDir(enginesDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		if strings.Contains(path, "/testdata") {
			return filepath.SkipDir
		}
		packages = append(packages, path)
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal/engines: %v", err)
	}

	checked := 0
	for _, dir := range packages {
		pkg, err := build.ImportDir(dir, 0)
		if err != nil {
			// A directory with no Go files is not a package. Skip rather than
			// fail: internal/engines itself may hold only subdirectories.
			continue
		}
		checked++

		rel, err := filepath.Rel(root, dir)
		if err != nil {
			t.Fatal(err)
		}
		pkgPath := "internal/" + filepath.ToSlash(rel)

		// Test imports are checked too. A test that dials out is still code in
		// this tree that opens a socket, and "only in tests" is how the first
		// exception gets made without anyone deciding to make one.
		imports := append(append([]string{}, pkg.Imports...), pkg.TestImports...)
		imports = append(imports, pkg.XTestImports...)
		sort.Strings(imports)

		for _, imp := range imports {
			why, isForbidden := matchForbidden(imp)
			if !isForbidden {
				continue
			}
			if isAllowed(pkgPath, imp) {
				continue
			}
			t.Errorf("%s imports %q: %s.\n"+
				"    If an engine genuinely needs this, add it to `allowed` in this file "+
				"WITH an ADR — deleting this guard is the other way to make the build pass, "+
				"and it is the wrong one.", pkgPath, imp, why)
		}
	}

	if checked == 0 {
		t.Fatal("no packages found under internal/engines; the guard passed over nothing")
	}
	t.Logf("checked %d package(s) under internal/engines; %d allowlist entries", checked, len(allowed))
}

func matchForbidden(imp string) (string, bool) {
	if why, ok := forbidden[imp]; ok {
		return why, true
	}
	// Prefix match, so net/netip and golang.org/x/sys/unix are caught too.
	for bad, why := range forbidden {
		if strings.HasPrefix(imp, bad+"/") {
			return why, true
		}
	}
	return "", false
}

func isAllowed(pkgPath, imp string) bool {
	for _, a := range allowed[pkgPath] {
		if imp == a || strings.HasPrefix(imp, a+"/") {
			return true
		}
	}
	return false
}

// The neutral list is not enforced — an engine may import anything not
// forbidden. It is here so that a reviewer reading this file can see what an
// engine's dependency set is expected to look like, and notice when one grows
// something that is technically permitted and still surprising.
func TestNeutralPrefixesAreDocumentedNotEnforced(t *testing.T) {
	if len(neutralPrefixes) == 0 {
		t.Error("the neutral list is empty; it exists to describe the expected shape")
	}
}
