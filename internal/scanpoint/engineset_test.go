package scanpoint_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/effaaykhan/cvap/internal/scanpoint"
)

// fakeEngine writes an executable that answers -capabilities with the given
// JSON and does nothing else.
//
// A real binary rather than a stub interface, because what is being tested is
// the interrogation — that the runtime learns an engine's kind by ASKING it,
// not by reading a label an operator supplied.
func fakeEngine(t *testing.T, name, capsJSON string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	script := "#!/bin/sh\nif [ \"$1\" = \"-capabilities\" ]; then\n  cat <<'EOF'\n" +
		capsJSON + "\nEOF\n  exit 0\nfi\nexit 1\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil { // #nosec G306 -- test fixture
		t.Fatal(err)
	}
	return path
}

const discoveryCaps = `[{"engine":"discovery","engine_version":"0.1.0","enabled":true}]`
const noopCaps = `[{"engine":"noop","engine_version":"0.0.0","enabled":true}]`

// TestTheBinaryDeclaresItsOwnKind.
func TestTheBinaryDeclaresItsOwnKind(t *testing.T) {
	set, err := scanpoint.NewEngineSet(context.Background(), []string{
		fakeEngine(t, "a", discoveryCaps),
		fakeEngine(t, "b", noopCaps),
	})
	if err != nil {
		t.Fatalf("NewEngineSet: %v", err)
	}

	if got := set.Kinds(); strings.Join(got, ",") != "discovery,noop" {
		t.Errorf("Kinds() = %v, want [discovery noop]", got)
	}
	if _, err := set.BinaryFor("discovery"); err != nil {
		t.Errorf("BinaryFor(discovery): %v", err)
	}
	if len(set.Capabilities()) != 2 {
		t.Errorf("Capabilities() has %d entries, want 2", len(set.Capabilities()))
	}
}

// TestTwoEnginesClaimingOneKindIsRefused.
//
// Not first-wins: "which engine did that scan run on" must have an answer, and a
// silent pick would make it depend on the order of an environment variable.
func TestTwoEnginesClaimingOneKindIsRefused(t *testing.T) {
	_, err := scanpoint.NewEngineSet(context.Background(), []string{
		fakeEngine(t, "a", discoveryCaps),
		fakeEngine(t, "b", discoveryCaps),
	})
	if err == nil {
		t.Fatal("two engines declaring the same kind were accepted")
	}
	if !strings.Contains(err.Error(), "discovery") {
		t.Errorf("the refusal does not name the contested kind: %v", err)
	}
}

// TestAJobForAnUnhostedEngineIsRefusedRatherThanRunElsewhere.
//
// ============================================================================
// The reason engine selection exists at all.
// ============================================================================
//
// The runtime used to host one binary and ignore JobAssignment.engine, which was
// harmless while the only engine could not open a socket. With a second engine
// that can, falling back to "whatever is configured" means Core dispatches
// discovery work and something else runs it — a scan on an engine nobody chose.
//
// A miss is a refusal. It means the capability handshake and the dispatch
// decision have disagreed, which is a thing an operator needs told, not routed
// around.
func TestAJobForAnUnhostedEngineIsRefusedRatherThanRunElsewhere(t *testing.T) {
	set, err := scanpoint.NewEngineSet(context.Background(), []string{
		fakeEngine(t, "noop", noopCaps),
	})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := set.BinaryFor("discovery"); err == nil {
		t.Error("a job for an engine this runtime does not host resolved to a binary")
	}
	if _, err := set.BinaryFor(""); err == nil {
		t.Error("a job naming no engine resolved to a binary")
	}
}

// TestAnEngineThatDeclaresNothingIsRefused. A binary that reports no
// capabilities has told the runtime nothing about what it is, and hosting it
// would mean its kind is whatever a later job claims.
func TestAnEngineThatDeclaresNothingIsRefused(t *testing.T) {
	if _, err := scanpoint.NewEngineSet(context.Background(), []string{
		fakeEngine(t, "empty", `[]`),
	}); err == nil {
		t.Error("an engine declaring no capabilities was accepted")
	}
	if _, err := scanpoint.NewEngineSet(context.Background(), nil); err == nil {
		t.Error("a runtime with no engines configured started")
	}
}
