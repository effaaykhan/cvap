package domain

import "sort"

// OS attribution from unauthenticated service evidence (ADR-061).
//
// ============================================================================
// This decision is PURE, like Resolve: correlate gathers the per-service OS
// hints and applies the verdict, and the ranking lives here so it is one place
// to read and one ADR to revise.
// ============================================================================
//
// A service osHint is a string the host chose to send (ADR-014), so attribution
// derived from it is non-authoritative and its confidence carries that. Banners
// name the distro FAMILY and never the release, so this function never sets a
// release: reaching `ubuntu804` needs a package-version->release map, which is
// knowledge-pipeline content (ADR-061). Family-only is the honest banner outcome.

// AttributionRole records how a service's hint related to the conclusion, so the
// basis of a claim is reachable when the claim is wrong.
type AttributionRole string

const (
	// RoleContributed: the winning hint, the one the family was taken from.
	RoleContributed AttributionRole = "contributed"
	// RoleAgreed: a hint naming the same family as the winner.
	RoleAgreed AttributionRole = "agreed"
	// RoleIgnored: a hint naming a DIFFERENT family, lost to precedence. Recorded
	// rather than dropped — the ignored hint is what exposes a wrong precedence.
	RoleIgnored AttributionRole = "ignored"
)

// OSEvidence is one service's contribution: the normalised family it suggested,
// with the service that said so and the confidence of that banner match.
type OSEvidence struct {
	Service    string // normalised protocol: ssh, http, smtp, ftp, smb
	Port       uint16
	Family     string // normalised lowercase: ubuntu, debian, windows
	Confidence float32
}

// AttributionSource is one line of the provenance chain.
type AttributionSource struct {
	Service string          `json:"service"`
	Port    uint16          `json:"port"`
	Family  string          `json:"family"`
	Role    AttributionRole `json:"role"`
}

// Attribution is the three-state outcome (ADR-061):
//   - DistroFamily == ""                     -> no attribution ("know nothing")
//   - DistroFamily != "", DistroRelease==nil -> family-only ("Ubuntu, no feed")
//   - both set                               -> resolved (matchable)
//
// The middle state is distinct from the first ON PURPOSE: a family-only host is a
// candidate for credentialed follow-up; a no-attribution host is not.
type Attribution struct {
	DistroFamily  string
	DistroRelease *string
	Confidence    float32
	Provenance    []AttributionSource
}

// osPrecedence ranks the services whose OS hint is trusted, highest first
// (ADR-061). SSH leads because its banner names the vendor package most
// precisely; SMB trails because its hint is a coarse platform, not a distro.
// This order is a DECISION with a review trigger, not a constant — the first
// host with a stale SSH build and a current SMB stack is the case that revises
// it, and the ignored hint in the provenance is what will show it.
var osPrecedence = []string{"ssh", "http", "https", "smtp", "ftp", "smb"}

func osRank(service string) int {
	for i, s := range osPrecedence {
		if s == service {
			// Highest precedence -> highest rank.
			return len(osPrecedence) - i
		}
	}
	return 0
}

// AttributeOS applies the precedence to the per-service hints and returns the
// three-state attribution with its provenance. Evidence with no family is
// ignored entirely (it is not OS evidence); if nothing carries a family the
// result is no-attribution.
func AttributeOS(ev []OSEvidence) Attribution {
	// Stable order: rank desc, then confidence desc, then service/port so the
	// verdict is deterministic for a given set of hints.
	sorted := make([]OSEvidence, 0, len(ev))
	for _, e := range ev {
		if e.Family != "" {
			sorted = append(sorted, e)
		}
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		ri, rj := osRank(sorted[i].Service), osRank(sorted[j].Service)
		if ri != rj {
			return ri > rj
		}
		if sorted[i].Confidence != sorted[j].Confidence {
			return sorted[i].Confidence > sorted[j].Confidence
		}
		if sorted[i].Service != sorted[j].Service {
			return sorted[i].Service < sorted[j].Service
		}
		return sorted[i].Port < sorted[j].Port
	})

	if len(sorted) == 0 {
		return Attribution{} // no attribution
	}

	winner := sorted[0]
	a := Attribution{
		DistroFamily: winner.Family,
		// Release stays nil: banners carry family, not release (ADR-061).
		DistroRelease: nil,
		Confidence:    winner.Confidence,
	}
	for i, e := range sorted {
		role := RoleAgreed
		switch {
		case i == 0:
			role = RoleContributed
		case e.Family != winner.Family:
			role = RoleIgnored
		}
		a.Provenance = append(a.Provenance, AttributionSource{
			Service: e.Service, Port: e.Port, Family: e.Family, Role: role,
		})
	}
	return a
}
