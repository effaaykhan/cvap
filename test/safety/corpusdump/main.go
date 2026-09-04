// Command corpusdump prints the runtime's built-in fingerprint corpus as the
// job fields an engine receives.
//
// ============================================================================
// The safety gate must exercise the REAL corpus, not a copy of it.
// ============================================================================
//
// The gate asserts that every packet went to an authorised target and that the
// engine's packet model matches the wire. Both claims are about the probes that
// actually ship — a hand-written probe list inside the gate would drift from
// internal/scanpoint the moment either changed, and the gate would go on
// reporting a clean run about a corpus nobody uses.
//
// So the gate asks this program, which asks scanpoint.BuiltinCorpus.
//
// It prints what the RUNTIME would hand an intrusive job: the probe list after
// the static safety policy, and the banner rules. It deliberately does not
// construct targets or ports; the gate supplies those.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/effaaykhan/cvap/internal/scanpoint"
)

func main() {
	corpus, rejected := scanpoint.BuiltinCorpus()
	for _, why := range rejected {
		// Never silently: a built-in refused by the policy is a bug in the
		// scan point, and the gate that reads this output would otherwise
		// report a clean run about a corpus quietly missing entries.
		fmt.Fprintln(os.Stderr, "corpusdump: built-in probe refused by the static policy:", why)
	}
	out, err := json.Marshal(map[string]any{
		"probes":              corpus.Probes,
		"banner_matches":      corpus.BannerMatches,
		"max_probes_per_port": scanpoint.PlatformMaxProbesPerPort,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "corpusdump:", err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}
