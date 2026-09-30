package domain

import "net/netip"

// Presence: does a host exist at this address, or did something merely answer for
// it? (ADR-108)
//
// The discovery engine probes an address, something completes a TCP handshake,
// and it emits an honest observation saying so. Nothing then decides whether that
// answer means a host is THERE. The judgement was implicit and always "yes",
// which is why it was never visibly wrong — until two /24s produced exactly
// 512 assets, 2x256, every address in both ranges including the four that cannot
// be hosts at all.
//
// This file is the verdict, and it is pure on purpose (ADR-108 decision 7): it
// WILL be wrong at first, and a rule that can be replayed over stored history is
// one that can be corrected without re-scanning a network.

// Presence is the verdict for one address.
type Presence string

const (
	// PresencePresent: evidence that a host is here. Something identified itself,
	// or answered in a way a range-wide responder does not.
	PresencePresent Presence = "present"

	// PresenceResponder: the answers at this address carry the signature of one
	// device answering for a range. NOT "nothing is here" — a claim this rule is
	// not entitled to make — but "nothing here has shown itself to be a host".
	PresenceResponder Presence = "responder"

	// PresenceUnknown: not enough evidence either way, by either of two routes.
	//
	// An address with no port evidence at all lands here, never in Responder:
	// "all of this address's ports are responder artefacts" is VACUOUSLY TRUE
	// when it has none, and a vacuous universal quietly suppressing addresses is
	// exactly the silent wrongness this ADR exists to end.
	//
	// An address that answered ANONYMOUSLY on ports carrying no responder
	// signature also lands here rather than in Present. Not being convicted is
	// not the same as being confirmed, and treating it as confirmation was the
	// first version's mistake — it asserted 219 hosts where 28 had identified
	// themselves.
	PresenceUnknown Presence = "unknown"
)

// PortEvidence is what one port looked like ACROSS the scanned population — the
// range-wide view, which is the only place the signal lives. A single address
// cannot tell you whether the thing answering on 5060 is a soft switch or a
// firewall wearing 473 addresses.
type PortEvidence struct {
	Port     int
	Protocol string

	// Answered is how many addresses in the population answered on this port.
	Answered int

	// Identities is how many DISTINCT product/version identities this port
	// resolved to across the population, and Identified how many rows carried a
	// product at all.
	Identities int
	Identified int
}

// AddressEvidence is one address's own answers.
type AddressEvidence struct {
	Addr netip.Addr

	// Ports the address answered on.
	Ports []PortRef

	// Identified is true when at least one of this address's services resolved to
	// a real product. One identification is enough: a middlebox completing
	// handshakes does not produce an OpenSSH version banner.
	Identified bool
}

// PortRef names a port on an address.
type PortRef struct {
	Port     int
	Protocol string
}

// Population is the scanned range's aggregate view.
type Population struct {
	// Addresses is how many addresses answered at all — the denominator the
	// ubiquity fraction is taken over.
	Addresses int

	// Ports is the range-wide evidence, keyed by port and protocol.
	Ports map[PortRef]PortEvidence

	// Networks are the CIDRs that were scanned, used to refuse the addresses that
	// cannot be hosts. Empty is allowed and simply means that check does not run.
	Networks []netip.Prefix
}

// ResponderPolicy is the tenant-tunable half (ADR-108 decision 3). The threshold
// is a POLICY LEVER and never a compiled constant: a network whose genuine
// services are uniform enough to collide with the responder signature must be
// able to move it without waiting for a release.
type ResponderPolicy struct {
	// UbiquityFraction is how much of the answering population a port must cover
	// before ubiquity counts against it at all. On the measured estate the
	// separation was 92.4% against 7.8%, so any sane default splits them.
	UbiquityFraction float64

	// MinPopulation is the smallest population the range-wide signal is trusted
	// over. Three addresses all running SSH is not evidence of a middlebox, it is
	// three servers, and a fraction computed over a handful of hosts is noise
	// wearing a percentage sign.
	MinPopulation int
}

// DefaultResponderPolicy is deliberately cautious: it suppresses nothing unless
// the port is both very widespread AND completely anonymous, and it ignores the
// range-wide signal entirely on small populations.
func DefaultResponderPolicy() ResponderPolicy {
	return ResponderPolicy{UbiquityFraction: 0.30, MinPopulation: 16}
}

// IsResponderArtefact decides whether a PORT (not an address) carries the
// signature of one device answering for a range.
//
// UBIQUITY IS NOT THE RULE, and getting that backwards is the trap this ADR was
// written to avoid. A managed fleet legitimately runs SSH on every host, so a
// rule keyed on frequency alone deletes the best-run estates first. The rule is
// that a responder ANSWERS AND THEN SAYS NOTHING: on the measured data six ports
// answered 473, 398, 330, 330, 247 and 179 times and resolved to ONE distinct
// identity and ZERO products between them, while port 22 answered 40 times and
// yielded TEN identities and 28 products. Diversity is the signal; frequency
// only says where to look.
func IsResponderArtefact(e PortEvidence, pop Population, p ResponderPolicy) bool {
	if pop.Addresses < p.MinPopulation {
		return false
	}
	// Anything that identified itself even once is a real service somewhere, and
	// a port that is a real service somewhere is not an artefact anywhere: a host
	// genuinely running it would be suppressed with the rest.
	if e.Identified > 0 || e.Identities > 1 {
		return false
	}
	return float64(e.Answered) >= p.UbiquityFraction*float64(pop.Addresses)
}

// IsImpossibleHost reports whether an address cannot be a host on any of the
// scanned networks: the network address or the broadcast address of an IPv4
// prefix (ADR-108 decision 4). This needs no threshold and no heuristic — it is
// arithmetic, and it caught four of the measured 512.
//
// A /31 and a /32 are excluded deliberately: RFC 3021 makes both addresses of a
// /31 usable, and a /32 is a single host. Treating their endpoints as impossible
// would suppress real hosts on point-to-point links.
func IsImpossibleHost(a netip.Addr, networks []netip.Prefix) bool {
	if !a.Is4() {
		return false // IPv6 has no broadcast address; the concept does not carry over
	}
	for _, n := range networks {
		if !n.Addr().Is4() || !n.Contains(a) || n.Bits() >= 31 {
			continue
		}
		if a == n.Masked().Addr() {
			return true // network address
		}
		if a == broadcast4(n) {
			return true
		}
	}
	return false
}

// broadcast4 is the all-ones host address of an IPv4 prefix.
func broadcast4(n netip.Prefix) netip.Addr {
	b := n.Masked().Addr().As4()
	host := 32 - n.Bits()
	for i := 0; i < host; i++ {
		b[3-i/8] |= 1 << (i % 8)
	}
	return netip.AddrFrom4(b)
}

// PresenceVerdict is the decision plus the reason that produced it. The reason
// travels because ADR-108 decision 6 requires the suppression to be STATED and
// arguable: an operator has to be able to see why an address was dropped from
// their estate and disagree with it.
type PresenceVerdict struct {
	Presence Presence
	Reason   string
}

// DecidePresence is the whole rule.
//
// Order matters and is not arbitrary. Impossible addresses are refused first
// because that is arithmetic and no amount of answering changes it. A single
// identification then settles the question the other way — a middlebox
// completing handshakes does not produce an OpenSSH version string, so one real
// product is worth more than any number of anonymous open ports. Only then does
// the range-wide signal get consulted, and only to suppress an address whose
// EVERY port is an artefact.
func DecidePresence(a AddressEvidence, pop Population, p ResponderPolicy) PresenceVerdict {
	// IDENTIFICATION OUTRANKS THE ARITHMETIC, and this order is the correction
	// ADR-108's own review trigger predicted: "revisit when a real host is
	// suppressed and an operator has to argue with the verdict". It took one run.
	//
	// ADR-108 decision 4 said an impossible address is refused "whatever answered
	// there". That was too absolute, because A SCAN TARGET IS AN INSTRUCTION, NOT A
	// DECLARATION OF THE SUBNET MASK. The measured estate had been scanned as a
	// /23, as two /24s AND as a /28; 10.200.10.15 is the broadcast address of that
	// /28 and an ordinary host under the wider two, and it answered with
	// "Dropbear SSH 2024.85" on port 22. A broadcast address does not run an SSH
	// daemon with a version string. The prefix arithmetic was applied to a range
	// somebody chose to scan, not to a subnet boundary.
	//
	// So a service that identified itself settles the question first. ADR-109
	// records the supersession.
	if a.Identified {
		return PresenceVerdict{PresencePresent,
			"a service here identified itself, which a device answering for a range does not do"}
	}
	if IsImpossibleHost(a.Addr, pop.Networks) {
		return PresenceVerdict{PresenceResponder,
			"the network or broadcast address of a scanned prefix, and nothing here identified itself"}
	}
	if len(a.Ports) == 0 {
		return PresenceVerdict{PresenceUnknown,
			"no port evidence at this address: nothing to judge, and silence is not a verdict"}
	}
	for _, ref := range a.Ports {
		ev, ok := pop.Ports[ref]
		if !ok || !IsResponderArtefact(ev, pop, p) {
			// NOT present. This is the correction that running the rule on a real
			// estate forced, and it matters more than any threshold: "no responder
			// signature" is the ABSENCE OF EVIDENCE OF A RESPONDER, which is not
			// evidence of a host. Decision 1 says existence is a verdict carrying
			// evidence, and an address whose every port answered anonymously
			// carries none — it has merely not been convicted.
			//
			// Measured: with this reading as `present`, 219 of 512 addresses were
			// asserted to hold hosts while only 28 had ever identified anything.
			// The other ~190 were rescued by two anonymous ports sitting just
			// under the ubiquity threshold. Tuning the threshold until that number
			// looked right would have been fitting the rule to one network;
			// requiring positive evidence is true everywhere.
			notConvicted := PresenceVerdict{PresenceUnknown,
				"answered, but nothing here identified itself and no port carries the range-wide responder signature: not convicted, not confirmed"}
			return notConvicted
		}
	}
	return PresenceVerdict{PresenceResponder,
		"every port here answers across the range and none ever identifies itself — the signature of one device wearing many addresses"}
}
