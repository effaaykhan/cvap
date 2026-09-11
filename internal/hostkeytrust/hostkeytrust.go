// Package hostkeytrust is the shape of JobAssignment.known_hosts: the host-key
// trust material a credentialed-host job verifies its target against, prefixed
// by a line that says WHERE that material came from.
//
// No I/O. Both ends of the wire import it — dispatch composes, the scan-point
// runtime parses — so the two sides cannot disagree about the format the way two
// hand-written copies would (ADR-091).
//
// # Why the source travels
//
// There are exactly two sources of a host key CVAP will trust, and no third:
//
//   - operator: lines pinned on the credential profile (migration 0042). A trust
//     root the operator chose, independent of what discovery saw.
//   - observed: the SHA256 fingerprint discovery captured for the target
//     (asset_identity_keys, key_type = 'ssh_hostkey'), seen at that address on
//     TWO DISTINCT earlier scans and on the port the engine dials (ADR-094,
//     asset_identity_key_sightings). What CVAP itself has seen the host present,
//     unauthenticated — twice, not once.
//
// Trust-on-first-use is not a source. A job with no material from either source
// is refused before an engine exists, and the engine refuses again if handed
// nothing usable (credhost.hostKeyCallback) — but the refusal that matters is the
// runtime's, because it happens before a process that can open a socket is
// spawned. The header is what lets the receiving side enforce that refusal on
// the CLAIM Core made, and lets Core's audit event record the same claim: an
// auditor reading "credential.granted" sees which mode applied, and a runtime
// reading the assignment sees the same word. Neither has to infer it from the
// shape of the lines.
package hostkeytrust

import (
	"errors"
	"fmt"
	"strings"
)

// Source is where the trust material came from.
type Source string

const (
	// SourceOperator: lines pinned on the credential profile by an operator.
	SourceOperator Source = "operator"
	// SourceObserved: fingerprints CVAP captured for the target on discovery.
	SourceObserved Source = "observed"
)

// HeaderPrefix begins the first line of the field. It is a known_hosts comment,
// so a parser that does not know about it — the engine's, which skips '#' lines
// — reads the material and ignores the claim, and a parser that does know about
// it can require it.
const HeaderPrefix = "# cvap-trust-source: "

// ErrNoHeader means the field carries no source line, so no claim was made.
var ErrNoHeader = errors.New("hostkeytrust: known_hosts carries no trust-source header")

// ErrUnknownSource means the header names a source this build does not know.
// Refused, not defaulted: a source added later must be a deliberate decision at
// both ends of the wire, and defaulting it to either existing one would make the
// audit record say something the runtime did not enforce.
var ErrUnknownSource = errors.New("hostkeytrust: unknown trust source")

// ErrNoMaterial means the header is present but no key line follows it. This is
// the trust-on-first-use shape, and it is refused by name.
var ErrNoMaterial = errors.New("hostkeytrust: no host-key material follows the header; trust-on-first-use is not permitted")

// Compose builds the wire value: the header, then the material verbatim.
//
// It refuses to compose an empty body rather than trusting the receiver to
// notice — Core must never put a TOFU-shaped assignment on the wire even though
// the runtime would refuse it, because a refusal at the receiver is an audit
// event about a claim Core should not have made.
func Compose(src Source, material string) (string, error) {
	switch src {
	case SourceOperator, SourceObserved:
	default:
		return "", fmt.Errorf("%w: %q", ErrUnknownSource, string(src))
	}
	if !hasMaterial(material) {
		return "", ErrNoMaterial
	}
	return HeaderPrefix + string(src) + "\n" + strings.TrimRight(material, "\n") + "\n", nil
}

// Parse reads the wire value back: the source the sender claimed, and the
// material that follows it. Every refusal names why.
func Parse(field string) (Source, string, error) {
	first, rest, _ := strings.Cut(field, "\n")
	first = strings.TrimSpace(first)
	if !strings.HasPrefix(first, HeaderPrefix) {
		return "", "", ErrNoHeader
	}
	src := Source(strings.TrimSpace(strings.TrimPrefix(first, HeaderPrefix)))
	switch src {
	case SourceOperator, SourceObserved:
	default:
		return "", "", fmt.Errorf("%w: %q", ErrUnknownSource, string(src))
	}
	if !hasMaterial(rest) {
		return "", "", ErrNoMaterial
	}
	return src, rest, nil
}

// hasMaterial reports whether at least one non-comment, non-blank line exists.
func hasMaterial(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return true
	}
	return false
}

// LinesCovering returns the known_hosts lines in material whose host field
// names target — "host", "host,other", "[host]:22". Comment and blank lines,
// hashed hosts and lines with no host field cover nothing. The result is what
// travels for that target: Core composes per task, so an operator pin written
// for one host is never presented as trust for another.
func LinesCovering(material, target string) []string {
	var out []string
	for _, line := range strings.Split(material, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "|") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		for _, h := range strings.Split(f[0], ",") {
			h = strings.TrimSpace(h)
			if h == target || h == "["+target+"]:22" {
				out = append(out, line)
				break
			}
		}
	}
	return out
}
