package scanpoint_test

import (
	"go/build"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestScanPointDoesNotImportCore holds the boundary internal/scanpoint/CLAUDE.md
// states: this package never imports internal/control or internal/store.
//
// The rule is not stylistic. A scan point runs in a network whose compromise the
// threat model assumes (ADR-020), and it reaches Core only over the four
// outbound services (ADR-005) — never the database. An import is how that stops
// being true: internal/store carries the connection pool, the RLS-aware queries
// and DATABASE_URL handling, and a scan point binary that linked it would ship
// the shape of the control plane's data access into a hostile network. It would
// also make ADR-004's "the broker is never reachable from a scan point"
// unenforceable, since dispatch's broker lives behind the same package.
//
// TRANSITIVE, because the interesting failure is indirect. A direct import is
// visible in review; a helper package added later that happens to pull in
// internal/store is not, and that is exactly the shape a scan-safety audit found
// in the engine guard — a package with an unremarkable name laundering a
// forbidden import one level down.
func TestScanPointDoesNotImportCore(t *testing.T) {
	const modulePath = "github.com/effaaykhan/cvap"

	forbidden := map[string]string{
		modulePath + "/internal/store": "the scan point reaches Core over gRPC, never the database (ADR-005); " +
			"linking the store ships the control plane's data access into a hostile network",
		modulePath + "/internal/control": "the control plane's services, including enrollment's issuer and CA; " +
			"a scan point consumes those over the wire and holds none of their code",
		modulePath + "/internal/dispatch": "Core's side of the protocol, and the broker behind it. " +
			"ADR-004 makes the broker unreachable from a scan point, which an import would undo",
	}

	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	var walk func(t *testing.T, pkg string, path []string)
	walk = func(t *testing.T, pkg string, path []string) {
		t.Helper()
		if seen[pkg] || !strings.HasPrefix(pkg, modulePath) {
			return
		}
		seen[pkg] = true

		if why, bad := forbidden[pkg]; bad {
			t.Errorf("%s reaches %s\n            via %s\n            %s",
				path[0], pkg, strings.Join(path, " -> "), why)
			return
		}

		dir := filepath.Join(root, strings.TrimPrefix(pkg, modulePath+"/"))
		p, err := build.ImportDir(dir, 0)
		if err != nil {
			t.Fatalf("reading %s: %v", dir, err)
		}
		// Imports, not TestImports: a test may legitimately reach for anything,
		// and this is about what the BINARY links.
		deps := append([]string(nil), p.Imports...)
		sort.Strings(deps)
		for _, d := range deps {
			walk(t, d, append(path, d))
		}
	}

	// Both the package and the binary that embeds it. The binary is the one
	// that actually ships, and it imports more than the package does.
	for _, entry := range []string{
		modulePath + "/internal/scanpoint",
		modulePath + "/cmd/cvap-scanpoint",
		modulePath + "/cmd/cvap-engine-noop",
	} {
		seen = map[string]bool{}
		walk(t, entry, []string{entry})
	}
}
