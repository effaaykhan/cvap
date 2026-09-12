package correlate

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/effaaykhan/cvap/internal/domain"
	"github.com/effaaykhan/cvap/internal/store"
)

// Reading identity out of observation payloads.
//
// ============================================================================
// Core parses what the engines emitted. It does not trust the shape.
// ============================================================================
//
// These structs mirror the engines' payloads and are deliberately separate
// types: internal/engines is not importable from here — the whole point of
// ADR-027's process boundary is that neither side depends on the other's
// internals — and a payload that fails to decode is a payload this build does
// not understand, which is a fact about the observation rather than an error.

// servicePayload mirrors the fingerprint engine's `service` observation.
//
// A subset: only what identity resolution and the derived service row need. A
// field added by the engine and not read here is not lost — the raw payload is
// on the observation, which is immutable and the record of what was actually
// seen.
type servicePayload struct {
	Address   string `json:"address"`
	Port      uint16 `json:"port"`
	Protocol  string `json:"protocol"`
	Service   string `json:"service"`
	Product   string `json:"product"`
	Version   string `json:"version"`
	Softmatch bool   `json:"softmatch"`

	Method     string `json:"method"`
	Solicited  bool   `json:"solicited"`
	SafetyMode string `json:"safety_mode"`
	Probe      string `json:"probe"`

	// OS is the non-authoritative platform hint the engine lifted from this
	// service's banner (ADR-061). Read here at last: the engine wrote it, the
	// wire carried it, and this struct did not model it — so attribution never
	// happened and the asset's OS stayed null. That was the fourth write-only-
	// field instance (phase-session-map §5.6), and it blocked P3.3.
	OS *osHintPayload `json:"os"`

	// Kept as raw JSON and stored as jsonb, because these are the objects week
	// 6's rules read and re-encoding them through a partial Go struct would
	// silently drop whatever this build does not model yet.
	TLS json.RawMessage `json:"tls"`
	SSH json.RawMessage `json:"ssh"`
}

// osHintPayload mirrors the engine's osHint object. Non-authoritative by
// construction (ADR-014): a banner is a string the host chose to send, so the
// derived attribution carries a confidence and never claims to be OS detection.
type osHintPayload struct {
	Hint   string `json:"hint"`
	Source string `json:"source"`
}

// packagePayload is what a credentialed-host engine's `package` observation carries
// (ADR-076/077/090). It is LIVE: the credhost fleet engine (ADR-086/087) emits it,
// and the correlator resolves attribution and supersedes inferred findings from it.
// The precedence rule that reads it was built dormant (S33, ADR-077) and activated on
// first contact in S41 — but ADR-089 found it unreachable behind a family gate, so
// ADR-090 lifted the exact read ahead of that gate. It is now genuinely live.
//
// Release is EXACT: read from /etc/os-release, not inferred from a banner band. The
// resolver lets it outrank the band vote (ADR-064) because ReleaseSource marks it
// read, not estimated — ground truth beats an estimate of it.
type packagePayload struct {
	Address       string `json:"address"`
	Release       string `json:"release"`        // VERSION_CODENAME or ID-major (rpm), read
	ReleaseSource string `json:"release_source"` // "os-release" = read on the host, authoritative
	// Family is the os-release ID ("ubuntu", "debian", "almalinux") — ground-truth
	// distro family, read on the host. It lets a credentialed observation resolve
	// attribution WITHOUT the service-inferred family gate (ADR-089): the exact
	// signal must not depend on the weaker inferred one. Empty on the dormant/
	// instrument shapes and on pre-ADR-089 payloads, which fall back to band voting.
	Family string `json:"family,omitempty"`
	// Installed is the exact inventory a credentialed-host engine read (empty on the
	// instrument shapes). It drives credentialed advisory matching — exact name +
	// version, no product->package map and no banner-version inference — and the
	// supersession of inferred findings (ADR-077/087/088). It is read separately from
	// the attribution fields above (credentialedAttribution reads Release/Source/
	// Family), so an observation without Installed still resolves the release.
	Installed []installedPackage `json:"installed,omitempty"`
}

// installedPackage is one exactly-known package: its source name (the key advisory
// data uses) and exact installed version. The comparator is not carried — it comes
// from the matched advisory row (advisory_fixed_packages.comparator, ADR-062).
type installedPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// addressed is the minimum any observation carries: which address it is about.
type addressed struct {
	Address string `json:"address"`
}

// tlsChain is the part of the certificate evidence identity needs.
type tlsChain struct {
	Chain []struct {
		Fingerprint string `json:"fingerprint"`
	} `json:"chain"`
}

type sshKey struct {
	Fingerprint string `json:"fingerprint"`
}

// groupByAddress turns a batch of observations into per-host evidence.
//
// The unit is a HOST, not an observation. Identity is a property of a host and
// the evidence for it is spread across several observations — the certificate
// from one service observation, the host key from another, the address from all
// of them. Resolving one observation at a time would hand the merge rule a
// single key and ask it to adjudicate corroboration it cannot see.
func groupByAddress(obs []store.Observation) []host {
	byAddr := map[string]*host{}
	order := []string{}

	for _, o := range obs {
		var a addressed
		if err := json.Unmarshal(o.Payload, &a); err != nil || a.Address == "" {
			// No address means nothing to group on and nothing to correlate
			// against. Left unresolved rather than forced into a bucket: an
			// observation Core cannot place is not one it should guess about.
			continue
		}
		// ONE spelling per address, before anything is compared or stored.
		// The review measured a non-canonical spelling ("10.77.6.010", an
		// unabbreviated IPv6, a "/24" suffix) grouping apart from the
		// canonical one, ageing the occupant out of its address and handing
		// it — and the credentialed trust root — to the newcomer. netip is
		// strict (no leading zeros, no mask, no zone) and renders one form; a
		// payload address it refuses is left unresolved like a missing one.
		ip, err := netip.ParseAddr(a.Address)
		if err != nil || ip.Zone() != "" {
			// netip accepts a zone ("fe80::1%eth0"); inet does not, and a
			// group the store cannot write pins the head of the batch for
			// the whole tenant (measured). Refused here, with the rest.
			continue
		}
		a.Address = ip.Unmap().String()
		h, ok := byAddr[a.Address]
		if !ok {
			h = &host{address: a.Address}
			byAddr[a.Address] = h
			order = append(order, a.Address)
		}
		h.obs = append(h.obs, o)
		if o.ObservedAt.After(h.seenAt) {
			h.seenAt = o.ObservedAt
		}
		h.keys = append(h.keys, keysFrom(o, a.Address)...)
	}

	out := make([]host, 0, len(order))
	for _, addr := range order {
		h := byAddr[addr]
		// The address itself, once per host rather than once per observation.
		// Counting it repeatedly would not change the merge rule — weak keys are
		// counted, not summed — but it would fill the queue's evidence with
		// duplicates.
		h.keys = append(h.keys, domain.IdentityKey{
			Type: domain.KeyIPWindow, Value: addr, Source: "net",
		})
		out = append(out, *h)
	}
	return out
}

// normProtocol is the one grammar for a service protocol on the identity path:
// absent means tcp, otherwise lowercase tcp/udp/sctp; anything else lifts no
// key. Every engine writes "tcp" today.
func normProtocol(p string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "", "tcp":
		return "tcp", true
	case "udp":
		return "udp", true
	case "sctp":
		return "sctp", true
	}
	return "", false
}

// keysFrom lifts ADR-007 identity keys out of one observation.
//
// Only the two a network scan can actually produce. The rest of ADR-007's table
// needs an agent, cloud metadata, a raw socket or a probe kind that does not
// exist — enumerated in internal/domain/identity.go so the gap is recorded where
// the code reads it rather than rediscovered.
func keysFrom(o store.Observation, address string) []domain.IdentityKey {
	if o.Type != "service" {
		return nil
	}
	var p servicePayload
	if err := json.Unmarshal(o.Payload, &p); err != nil {
		return nil
	}
	// The copied evidence is what the STORE reads the port back from
	// (Retire, LastSeenAt, the one-live-key-per-port index) with an exact
	// jsonb key, while Go decodes names case-insensitively: a payload spelling
	// it "Port" would yield a source here and no port there — a key nothing
	// could ever retire or contradict (measured). No exact "port": no key.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(o.Payload, &raw); err != nil {
		return nil
	}
	if _, ok := raw["port"]; !ok || p.Port == 0 {
		return nil
	}
	// The protocol is free text on the wire and part of the key's Source,
	// which the one-live-key-per-service index mirrors: an unknown or
	// differently-cased spelling would be a distinct service to the domain
	// and a refused write to the store, retried every sweep. One grammar.
	proto, ok := normProtocol(p.Protocol)
	if !ok {
		return nil
	}

	// The SOURCE is the service that produced the key, and it is what makes two
	// moderate keys independent (ADR-049 §5). Two certificates from two ports of
	// one host are one fact observed twice; naming the port is what stops them
	// corroborating each other.
	source := fmt.Sprintf("%d/%s", p.Port, proto)

	var out []domain.IdentityKey

	if len(p.SSH) > 0 {
		var k sshKey
		if err := json.Unmarshal(p.SSH, &k); err == nil && k.Fingerprint != "" {
			out = append(out, domain.IdentityKey{
				Type: domain.KeySSHHostKey, Value: k.Fingerprint, Source: source,
				ObservationID: o.ID, Payload: o.Payload,
			})
		}
	}
	if len(p.TLS) > 0 {
		var c tlsChain
		if err := json.Unmarshal(p.TLS, &c); err == nil && len(c.Chain) > 0 &&
			c.Chain[0].Fingerprint != "" {
			// The LEAF, which is index 0 of what the peer presented. An
			// intermediate or a root is shared across every host that chains to
			// it, so using one as an identity key would merge an entire estate
			// into a single asset.
			out = append(out, domain.IdentityKey{
				Type: domain.KeyServiceCert, Value: c.Chain[0].Fingerprint, Source: source,
				ObservationID: o.ID, Payload: o.Payload,
			})
		}
	}
	return out
}

// observedWindow is how far back a sweep looks. Bounded because
// `ListUnresolved` reads a partitioned table and an unbounded range would scan
// every partition that has ever existed.
var observedWindow = 90 * 24 * time.Hour
