package scanpoint

import (
	"context"
	"fmt"
	"sort"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
)

// EngineSet is the engines this runtime may host, keyed by the kind each one
// declares about itself.
//
// ============================================================================
// The binary is the authority on what it is. The operator names paths only.
// ============================================================================
//
// The runtime used to host exactly one engine and ignore JobAssignment.engine
// entirely — which was harmless while the only engine was the no-op, and stops
// being harmless the moment a second one exists that can put a packet on a
// wire. A discovery job dispatched to whatever binary happened to be configured
// is a scan running on an engine Core did not choose.
//
// The mapping is built by ASKING each binary, not by reading a configured
// label. An operator-supplied `kind=path` map would be a second statement of a
// fact the binary already reports through -capabilities and Core already
// receives at enrolment — and two statements of one fact are free to disagree,
// with the runtime believing the wrong one.
type EngineSet struct {
	byKind map[string]string
	caps   []*scanpointv1.Capability
}

// NewEngineSet interrogates every configured binary.
//
// Refuses on a duplicate kind rather than picking one. "Which engine did that
// scan run on" has to have an answer, and a silent first-wins would make it
// depend on the order of an environment variable.
func NewEngineSet(ctx context.Context, binaries []string) (*EngineSet, error) {
	if len(binaries) == 0 {
		return nil, fmt.Errorf("scanpoint: no engine binaries configured")
	}

	set := &EngineSet{byKind: map[string]string{}}
	for _, bin := range binaries {
		caps, err := EngineCapabilities(ctx, bin)
		if err != nil {
			return nil, err
		}
		if len(caps) == 0 {
			return nil, fmt.Errorf("scanpoint: engine %s declares no capabilities", bin)
		}
		for _, c := range caps {
			kind := c.GetEngine()
			if kind == "" {
				return nil, fmt.Errorf("scanpoint: engine %s declares a capability with no engine kind", bin)
			}
			if prior, dup := set.byKind[kind]; dup {
				return nil, fmt.Errorf(
					"scanpoint: engines %s and %s both declare engine kind %q; "+
						"which one a job ran on would depend on configuration order",
					prior, bin, kind)
			}
			set.byKind[kind] = bin
		}
		set.caps = append(set.caps, caps...)
	}

	// Stable order, so the capability list Core receives does not churn with
	// the order of an environment variable.
	sort.Slice(set.caps, func(i, j int) bool {
		return set.caps[i].GetEngine() < set.caps[j].GetEngine()
	})
	return set, nil
}

// Capabilities is what this scan point declares at enrolment: the union across
// every hosted engine.
//
// Self-asserted and a CEILING, as it always was — Core intersects it with what
// this scan point is independently authorised to run, so declaring a capability
// cannot obtain work it is not permitted to do.
func (s *EngineSet) Capabilities() []*scanpointv1.Capability { return s.caps }

// BinaryFor resolves a job's declared engine kind to the binary that runs it.
//
// A miss is a REFUSAL, not a fallback to whatever is available. Core dispatched
// work for an engine this scan point does not host, which means the capability
// handshake and the dispatch decision disagree — and running it on a different
// engine would turn that disagreement into a scan nobody chose.
func (s *EngineSet) BinaryFor(kind string) (string, error) {
	if kind == "" {
		return "", fmt.Errorf("scanpoint: job assignment names no engine")
	}
	bin, ok := s.byKind[kind]
	if !ok {
		return "", fmt.Errorf("scanpoint: no hosted engine declares kind %q", kind)
	}
	return bin, nil
}

// Kinds lists what this runtime can run, for logging and for the error above.
func (s *EngineSet) Kinds() []string {
	out := make([]string, 0, len(s.byKind))
	for k := range s.byKind {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
