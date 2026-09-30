package domain_test

import (
	"net/netip"
	"testing"

	"github.com/effaaykhan/cvap/internal/domain"
)

// mutate:subject internal/domain/presence.go
// mutate:test    ./internal/domain/ -run TestPresence|TestResponderArtefact|TestImpossibleHost|TestAnAddressWithNoPorts|TestOneIdentification|TestUbiquityAlone|TestASmallPopulation|TestAPortWithNo|TestNotConvicted|TestEveryVerdictCarries|TestAnIdentifiedServiceOutranks|TestAnIdentifiedAddressIsNever
//
// mutate:case    ubiquity alone suppresses a port, so a uniformly managed estate is deleted
// mutate:old     if e.Identified > 0 || e.Identities > 1 {
// mutate:new     if false {
//
// mutate:case    an address with no ports is suppressed by a vacuous universal
// mutate:old     if len(a.Ports) == 0 {
// mutate:new     if false {
//
// mutate:case    the small-population guard is dropped, so three SSH servers read as a middlebox
// mutate:old     if pop.Addresses < p.MinPopulation {
// mutate:new     if false {
//
// mutate:case    prefix arithmetic outranks an identified service, suppressing a real host
// mutate:old     if a.Identified {
// mutate:new     if false || a.Identified && false {
//
// mutate:case    absence of a responder signature is treated as evidence of a host
// Anchored on the NAMED verdict, not on `return PresenceVerdict{PresenceUnknown,`
// which matches twice in this file — mutate.py refuses an ambiguous anchor
// ("ANCHOR LOST: the mutation tests nothing") rather than guessing, and it is
// right to: a directive that still reads correctly while testing nothing is the
// worst shape a guard can take.
// mutate:old     notConvicted := PresenceVerdict{PresenceUnknown,
// mutate:new     notConvicted := PresenceVerdict{PresencePresent,
//
// mutate:case    a /31's endpoints are treated as impossible, suppressing real point-to-point hosts
// mutate:old     if !n.Addr().Is4() || !n.Contains(a) || n.Bits() >= 31 {
// mutate:new     if !n.Addr().Is4() || !n.Contains(a) {

func p24(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func ip(s string) netip.Addr    { return netip.MustParseAddr(s) }

// The measured estate, as the population the rule actually saw (ADR-108): six
// ports answering hundreds of times with one identity and no products between
// them, and port 22 answering 40 times with ten identities.
func measuredPopulation() domain.Population {
	ports := map[domain.PortRef]domain.PortEvidence{}
	for _, x := range []struct {
		port, answered, identities, identified int
	}{
		{5060, 473, 1, 0}, {2000, 398, 1, 0}, {135, 330, 1, 0},
		{445, 330, 1, 0}, {3389, 247, 1, 0}, {80, 179, 1, 0},
		{22, 40, 10, 28},
	} {
		ref := domain.PortRef{Port: x.port, Protocol: "tcp"}
		ports[ref] = domain.PortEvidence{Port: x.port, Protocol: "tcp",
			Answered: x.answered, Identities: x.identities, Identified: x.identified}
	}
	return domain.Population{Addresses: 512, Ports: ports,
		Networks: []netip.Prefix{p24("10.200.10.0/24"), p24("10.200.11.0/24")}}
}

func ref(port int) domain.PortRef { return domain.PortRef{Port: port, Protocol: "tcp"} }

// The six anonymous ports are artefacts; port 22 is not. This is the whole
// discriminator, run against the numbers that motivated the ADR.
func TestResponderArtefactKeysOnIdentityNotFrequency(t *testing.T) {
	pop := measuredPopulation()
	pol := domain.DefaultResponderPolicy()
	for _, port := range []int{5060, 2000, 135, 445, 3389, 80} {
		if !domain.IsResponderArtefact(pop.Ports[ref(port)], pop, pol) {
			t.Errorf("port %d answers on %d of %d addresses and never identifies itself; it should read as a responder artefact",
				port, pop.Ports[ref(port)].Answered, pop.Addresses)
		}
	}
	if domain.IsResponderArtefact(pop.Ports[ref(22)], pop, pol) {
		t.Error("port 22 yielded 10 distinct identities and 28 products; treating it as an artefact would suppress every real SSH host")
	}
}

// The trap the ADR was written to avoid: a fleet that legitimately runs one
// service everywhere must NOT be suppressed. Ubiquity says where to look;
// identity decides.
func TestUbiquityAloneIsNotEnough(t *testing.T) {
	pol := domain.DefaultResponderPolicy()
	// SSH on every single host, and it identifies itself every time.
	universal := domain.PortEvidence{Port: 22, Protocol: "tcp", Answered: 500, Identities: 7, Identified: 500}
	pop := domain.Population{Addresses: 500, Ports: map[domain.PortRef]domain.PortEvidence{ref(22): universal}}
	if domain.IsResponderArtefact(universal, pop, pol) {
		t.Fatal("a port on 100% of hosts that identifies itself on 100% of them was called an artefact — this deletes the best-managed estates first, which is exactly backwards")
	}
	// One identification is enough, even against total ubiquity and a single
	// identity: a real service somewhere is not an artefact anywhere.
	barely := domain.PortEvidence{Port: 22, Protocol: "tcp", Answered: 500, Identities: 1, Identified: 1}
	if domain.IsResponderArtefact(barely, pop, pol) {
		t.Error("a single identification did not rescue the port; a host genuinely running it would be suppressed with the responders")
	}
}

// A small population cannot support the range-wide inference. Three servers all
// running SSH is three servers.
func TestASmallPopulationIsNotEvidence(t *testing.T) {
	pol := domain.DefaultResponderPolicy()
	ev := domain.PortEvidence{Port: 5060, Protocol: "tcp", Answered: 3, Identities: 1, Identified: 0}
	pop := domain.Population{Addresses: 3, Ports: map[domain.PortRef]domain.PortEvidence{ref(5060): ev}}
	if domain.IsResponderArtefact(ev, pop, pol) {
		t.Errorf("3 of 3 addresses was treated as a middlebox signature; a fraction over a handful of hosts is noise wearing a percentage sign")
	}
}

// Arithmetic, not heuristic: four of the measured 512 were these.
func TestImpossibleHostIsArithmetic(t *testing.T) {
	nets := []netip.Prefix{p24("10.200.10.0/24"), p24("10.200.11.0/24")}
	for _, a := range []string{"10.200.10.0", "10.200.10.255", "10.200.11.0", "10.200.11.255"} {
		if !domain.IsImpossibleHost(ip(a), nets) {
			t.Errorf("%s is a network or broadcast address and cannot be a host", a)
		}
	}
	for _, a := range []string{"10.200.10.1", "10.200.10.254", "10.200.11.7"} {
		if domain.IsImpossibleHost(ip(a), nets) {
			t.Errorf("%s is an ordinary host address and must not be refused", a)
		}
	}
	// RFC 3021: both addresses of a /31 are usable, and a /32 is one host.
	// Applying broadcast arithmetic to them would suppress real point-to-point hosts.
	for _, tc := range []struct{ addr, prefix string }{
		{"10.0.0.0", "10.0.0.0/31"}, {"10.0.0.1", "10.0.0.0/31"}, {"10.0.0.5", "10.0.0.5/32"},
	} {
		if domain.IsImpossibleHost(ip(tc.addr), []netip.Prefix{p24(tc.prefix)}) {
			t.Errorf("%s in %s was refused; RFC 3021 makes /31 endpoints usable and a /32 is a single host", tc.addr, tc.prefix)
		}
	}
	// IPv6 has no broadcast address; the concept must not be carried over.
	if domain.IsImpossibleHost(ip("2001:db8::"), []netip.Prefix{p24("2001:db8::/64")}) {
		t.Error("an IPv6 prefix's base address was refused as a broadcast address, which IPv6 does not have")
	}
}

// THE VACUOUS UNIVERSAL. "Every port at this address is an artefact" is trivially
// true when the address has no ports, and a rule that let that suppress an
// address would silently drop exactly the hosts it has no evidence about — the
// 39 addresses in the measured estate that carried zero services.
func TestAnAddressWithNoPortsIsUnknownNotSuppressed(t *testing.T) {
	pop := measuredPopulation()
	v := domain.DecidePresence(domain.AddressEvidence{Addr: ip("10.200.10.7")}, pop, domain.DefaultResponderPolicy())
	if v.Presence == domain.PresenceResponder {
		t.Fatalf("an address with no port evidence was SUPPRESSED (%q). 'every port is an artefact' is vacuously true with no ports; silence is not a verdict", v.Reason)
	}
	if v.Presence != domain.PresenceUnknown {
		t.Errorf("presence = %q, want %q", v.Presence, domain.PresenceUnknown)
	}
}

// One identification outranks any number of anonymous open ports, because a
// middlebox completing handshakes does not produce a version banner.
func TestOneIdentificationSettlesIt(t *testing.T) {
	pop := measuredPopulation()
	// A real host hiding behind the same middlebox: every one of its ports is an
	// artefact by the range-wide signal, but one of them identified itself. This
	// is the case the ADR expects to bite, and it must resolve to present.
	a := domain.AddressEvidence{
		Addr:       ip("10.200.10.6"),
		Ports:      []domain.PortRef{ref(5060), ref(2000), ref(445)},
		Identified: true,
	}
	v := domain.DecidePresence(a, pop, domain.DefaultResponderPolicy())
	if v.Presence != domain.PresencePresent {
		t.Fatalf("a host with an identified service was suppressed (%q, %q); one real product outranks the range-wide signal", v.Presence, v.Reason)
	}
}

// The end-to-end verdicts on the measured estate.
func TestPresenceOnTheMeasuredEstate(t *testing.T) {
	pop := measuredPopulation()
	pol := domain.DefaultResponderPolicy()
	cases := []struct {
		name string
		a    domain.AddressEvidence
		want domain.Presence
	}{
		{"phantom: only anonymous range-wide ports",
			domain.AddressEvidence{Addr: ip("10.200.10.42"), Ports: []domain.PortRef{ref(5060), ref(2000)}},
			domain.PresenceResponder},
		{"real: SSH answered and identified",
			domain.AddressEvidence{Addr: ip("10.200.10.6"), Ports: []domain.PortRef{ref(22)}, Identified: true},
			domain.PresencePresent},
		{"NOT convicted is not confirmed: answered anonymously on a non-artefact port",
			domain.AddressEvidence{Addr: ip("10.200.10.9"), Ports: []domain.PortRef{ref(22)}},
			domain.PresenceUnknown},
		{"impossible: broadcast address with five open ports",
			domain.AddressEvidence{Addr: ip("10.200.11.255"), Ports: []domain.PortRef{ref(5060)}},
			domain.PresenceResponder},
		{"unknown: nothing to judge",
			domain.AddressEvidence{Addr: ip("10.200.10.77")},
			domain.PresenceUnknown},
	}
	for _, c := range cases {
		v := domain.DecidePresence(c.a, pop, pol)
		if v.Presence != c.want {
			t.Errorf("%s: presence = %q, want %q (reason: %s)", c.name, v.Presence, c.want, v.Reason)
		}
		if v.Reason == "" {
			t.Errorf("%s: verdict carries no reason; ADR-108 decision 6 requires the suppression to be arguable", c.name)
		}
	}
}

// A port the population has no evidence for must not suppress an address. A
// missing map entry is absence of evidence, not evidence of a responder.
func TestAPortWithNoPopulationEvidenceDoesNotSuppress(t *testing.T) {
	pop := measuredPopulation()
	a := domain.AddressEvidence{Addr: ip("10.200.10.31"), Ports: []domain.PortRef{{Port: 9999, Protocol: "tcp"}}}
	if v := domain.DecidePresence(a, pop, domain.DefaultResponderPolicy()); v.Presence == domain.PresenceResponder {
		t.Errorf("an address was SUPPRESSED on a port the population has no evidence for; a missing entry is absence of evidence, not evidence of a responder")
	}
}

// The correction that running the rule on a real estate forced, and the one worth
// a test of its own: an address that answered ANONYMOUSLY on a port carrying no
// responder signature is NOT present. "No responder signature" is the absence of
// evidence of a responder, which is not evidence of a host.
//
// Measured before the fix: 219 of 512 addresses were asserted to hold hosts while
// only 28 had ever identified anything, the other ~190 rescued by two anonymous
// ports sitting just below the ubiquity threshold. The temptation was to lower the
// threshold until that number looked right, which would have fitted the rule to
// one network; requiring positive evidence is true everywhere.
func TestNotConvictedIsNotConfirmed(t *testing.T) {
	pol := domain.DefaultResponderPolicy()
	// A port answering on 8% of the population, anonymously — below any ubiquity
	// threshold, and it has never identified itself.
	quiet := domain.PortEvidence{Port: 7070, Protocol: "tcp", Answered: 48, Identities: 1, Identified: 0}
	pop := domain.Population{Addresses: 512, Ports: map[domain.PortRef]domain.PortEvidence{ref(7070): quiet}}
	if domain.IsResponderArtefact(quiet, pop, pol) {
		t.Fatal("precondition: 7070 at 8% should not be an artefact")
	}

	v := domain.DecidePresence(
		domain.AddressEvidence{Addr: ip("10.200.10.55"), Ports: []domain.PortRef{ref(7070)}}, pop, pol)
	if v.Presence == domain.PresencePresent {
		t.Fatalf("an address that only answered anonymously was asserted PRESENT (%q). Existence is a verdict carrying evidence (ADR-108 decision 1); this address carries none, it has merely not been convicted", v.Reason)
	}
	if v.Presence != domain.PresenceUnknown {
		t.Errorf("presence = %q, want %q", v.Presence, domain.PresenceUnknown)
	}

	// And the same address WITH an identification is present — positive evidence
	// is what moves it, nothing else.
	v2 := domain.DecidePresence(
		domain.AddressEvidence{Addr: ip("10.200.10.55"), Ports: []domain.PortRef{ref(7070)}, Identified: true}, pop, pol)
	if v2.Presence != domain.PresencePresent {
		t.Errorf("presence = %q with an identified service, want present", v2.Presence)
	}
}

// Every verdict carries a reason, `unknown` included. It is a real judgement
// reached two different ways, and an operator asking why an address is unjudged
// deserves the same answer as one asking why it was suppressed.
func TestEveryVerdictCarriesAReason(t *testing.T) {
	pop := measuredPopulation()
	pol := domain.DefaultResponderPolicy()
	for _, a := range []domain.AddressEvidence{
		{Addr: ip("10.200.10.42"), Ports: []domain.PortRef{ref(5060)}},
		{Addr: ip("10.200.10.6"), Ports: []domain.PortRef{ref(22)}, Identified: true},
		{Addr: ip("10.200.11.255"), Ports: []domain.PortRef{ref(5060)}},
		{Addr: ip("10.200.10.77")},
		{Addr: ip("10.200.10.9"), Ports: []domain.PortRef{ref(22)}},
	} {
		if v := domain.DecidePresence(a, pop, pol); v.Reason == "" {
			t.Errorf("%s: verdict %q carries no reason; ADR-108 decision 6 requires it be arguable", a.Addr, v.Presence)
		}
	}
}

// ADR-109: an identified service outranks the impossible-address arithmetic.
//
// The case that forced it, from the first real run: 10.200.10.15 answered with
// "Dropbear SSH 2024.85" on port 22 and was suppressed as the broadcast address of
// a scanned 10.200.10.0/28 — while the same estate had also been scanned as a /23
// and as two /24s, under which .15 is an ordinary host. A broadcast address does
// not run an SSH daemon with a version string. A scan target is an instruction,
// not a declaration of the subnet mask.
func TestAnIdentifiedServiceOutranksPrefixArithmetic(t *testing.T) {
	// Exactly the measured topology: the same address is a broadcast under one
	// scanned prefix and an ordinary host under the others.
	pop := domain.Population{
		Addresses: 512,
		Ports:     map[domain.PortRef]domain.PortEvidence{},
		Networks: []netip.Prefix{
			p24("10.200.10.0/23"), p24("10.200.10.0/24"),
			p24("10.200.11.0/24"), p24("10.200.10.0/28"),
		},
	}
	pol := domain.DefaultResponderPolicy()
	addr := ip("10.200.10.15")

	// Precondition: the arithmetic alone does call it impossible.
	if !domain.IsImpossibleHost(addr, pop.Networks) {
		t.Fatal("precondition: .15 is the broadcast address of the scanned /28")
	}

	// With an identification it is present anyway.
	withID := domain.DecidePresence(domain.AddressEvidence{Addr: addr, Identified: true}, pop, pol)
	if withID.Presence != domain.PresencePresent {
		t.Errorf("a host answering with an SSH version banner was suppressed as a broadcast address (%q, %q); the /28 was a scan range, not a subnet boundary", withID.Presence, withID.Reason)
	}

	// Without one, the arithmetic still stands — it is the only evidence there.
	noID := domain.DecidePresence(domain.AddressEvidence{Addr: addr, Ports: []domain.PortRef{ref(5060)}}, pop, pol)
	if noID.Presence != domain.PresenceResponder {
		t.Errorf("presence = %q for an unidentified broadcast-shaped address, want responder: with no positive evidence the arithmetic is all there is", noID.Presence)
	}
}

// THE INVARIANT, not an example of it: an address carrying an identified service
// is NEVER suppressed, whatever else is true of it.
//
// This exists because the violation was a line ORDER, and a fixed line order is
// not a guarantee — the next edit reorders it back. Enumerating the hostile
// combinations is cheap; rediscovering this against a real network is not.
func TestAnIdentifiedAddressIsNeverSuppressed(t *testing.T) {
	pol := domain.DefaultResponderPolicy()
	pop := measuredPopulation()
	// Every scanned-prefix shape, including ones that make the address look
	// impossible, combined with ports that are all responder artefacts.
	pop.Networks = append(pop.Networks, p24("10.200.10.0/28"), p24("10.200.10.0/23"))

	hostile := []domain.AddressEvidence{
		{Addr: ip("10.200.10.0"), Identified: true},                                                           // network address
		{Addr: ip("10.200.10.255"), Identified: true},                                                         // broadcast
		{Addr: ip("10.200.10.15"), Identified: true},                                                          // broadcast of the /28
		{Addr: ip("10.200.10.42"), Identified: true, Ports: []domain.PortRef{ref(5060), ref(2000), ref(445)}}, // every port an artefact
		{Addr: ip("10.200.11.255"), Identified: true, Ports: []domain.PortRef{ref(5060)}},                     // both at once
	}
	for _, a := range hostile {
		v := domain.DecidePresence(a, pop, pol)
		if v.Presence == domain.PresenceResponder {
			t.Errorf("%s carried an identified service and was SUPPRESSED (%q). A device answering for a range does not produce a version banner; suppressing an identified host is the one outcome this rule must never reach", a.Addr, v.Reason)
		}
	}
}
