// Package scopetest carries the scope decision table both enforcement sites are
// tested against.
//
// ADR-024 requires the scan point runtime to check scope again, independently of
// Core. Sharing internal/scope makes the two evaluate rules identically, but it
// does not make them CALL it identically: a site that stopped passing the
// exclusion list, or passed the allowlist in place of it, or skipped the check
// for one class of target, would still compile and would still pass whatever
// unit tests it has of its own. That is the divergence worth catching, because
// it is invisible from either side alone.
//
// So the table lives here and both sites run their own decision path over it —
// internal/dispatch through the check offerWork makes before it builds an
// assignment, internal/scanpoint through the gate an engine's targets pass. A
// disagreement fails the build of whichever side drifted.
//
// A non-test package because two packages import it. Nothing here reaches
// production: it is only ever referenced from _test.go files, and it holds no
// logic — a second implementation of the matcher living in the test fixture
// would defeat the entire point.
package scopetest

// Case is one scope decision, stated once for both sites.
type Case struct {
	Name       string
	Target     string
	Allowed    []string
	Exclusions []string
	Want       bool
}

// Cases is the shared table.
//
// Every entry is a decision an operator would recognise, not a fuzz input. When
// a case is added because a bug was found, name the bug in the case name — the
// table is also the record of what the two sites have disagreed about before.
var Cases = []Case{
	{
		Name:    "inside the only allow rule",
		Target:  "192.0.2.11",
		Allowed: []string{"192.0.2.0/24"},
		Want:    true,
	},
	{
		Name:       "excluded, even though an allow covers it",
		Target:     "192.0.2.5",
		Allowed:    []string{"192.0.2.0/24"},
		Exclusions: []string{"192.0.2.5/32"},
		Want:       false,
	},
	{
		Name:    "outside every allow rule",
		Target:  "198.51.100.7",
		Allowed: []string{"192.0.2.0/24"},
		Want:    false,
	},
	{
		// ADR-037. The one list whose empty case DENIES.
		Name:   "an empty allowlist denies everything",
		Target: "192.0.2.11",
		Want:   false,
	},
	{
		Name:    "exact hostname allow",
		Target:  "lab.internal",
		Allowed: []string{"lab.internal"},
		Want:    true,
	},
	{
		Name:    "hostname comparison is case-insensitive",
		Target:  "LAB.INTERNAL",
		Allowed: []string{"lab.internal"},
		Want:    true,
	},
	{
		// Nothing resolves DNS on either side, deliberately: a resolution done
		// at planning is a different answer from the one the scan point would
		// get. Stated as a case so the property is asserted rather than assumed.
		Name:    "a hostname allow does not cover the address it resolves to",
		Target:  "192.0.2.11",
		Allowed: []string{"lab.internal"},
		Want:    false,
	},
	{
		// The oldest way past an address denylist.
		Name:       "the v4-mapped form of an excluded address is excluded",
		Target:     "::ffff:192.0.2.5",
		Allowed:    []string{"192.0.2.0/24"},
		Exclusions: []string{"192.0.2.5"},
		Want:       false,
	},
	{
		// Found by a safety audit in session 8e: the TARGET was unmapped and
		// the RULE was not, so a deny written in v4-mapped CIDR form excluded
		// nothing while the bare-address form worked. Writing a deny in that
		// form must not be the way to disarm it.
		Name:       "a v4-mapped CIDR exclusion covers the v4 host it names",
		Target:     "192.0.2.5",
		Allowed:    []string{"192.0.2.0/24"},
		Exclusions: []string{"::ffff:192.0.2.0/120"},
		Want:       false,
	},
	{
		// The prefix length has to move with the address, not merely survive
		// it: /126 over a v4-mapped address is a /30 over the v4 one, covering
		// .0 through .3. A conversion that kept the bits would make this a /126
		// over four bytes and exclude nothing; one that dropped them to /32
		// would exclude a single host. Both are wrong in a way the case above
		// cannot see, because there every answer is "excluded".
		Name:       "and does not cover a host outside the narrowed range",
		Target:     "192.0.2.150",
		Allowed:    []string{"192.0.2.0/24"},
		Exclusions: []string{"::ffff:192.0.2.0/126"},
		Want:       true,
	},
	{
		Name:       "while a host inside it is still excluded",
		Target:     "192.0.2.2",
		Allowed:    []string{"192.0.2.0/24"},
		Exclusions: []string{"::ffff:192.0.2.0/126"},
		Want:       false,
	},
	{
		Name:       "an excluded address written as a host prefix",
		Target:     "192.0.2.5/32",
		Allowed:    []string{"192.0.2.0/24"},
		Exclusions: []string{"192.0.2.5"},
		Want:       false,
	},
	{
		Name:    "an empty target is not a target",
		Target:  "",
		Allowed: []string{"192.0.2.0/24"},
		Want:    false,
	},
	{
		Name:    "whitespace is not a target either",
		Target:  "   ",
		Allowed: []string{"192.0.2.0/24"},
		Want:    false,
	},
	{
		// A CIDR-shaped task target matches no CIDR allow rule, because a rule
		// is compared against an ADDRESS. Fail-safe, and asserted here so that
		// the first planner emitting a range sweep finds the decision written
		// down rather than discovering it as a wave of scope_violation_halt.
		Name:    "a range-shaped target is not covered by the range that contains it",
		Target:  "192.0.2.0/24",
		Allowed: []string{"192.0.2.0/24"},
		Want:    false,
	},
	{
		Name:       "exclusions win regardless of order",
		Target:     "192.0.2.5",
		Allowed:    []string{"192.0.2.5", "192.0.2.0/24"},
		Exclusions: []string{"192.0.2.0/24"},
		Want:       false,
	},
	{
		// netip.Prefix.Contains is false for ANY zoned address, so before the
		// zone was stripped no CIDR exclusion could match a zoned target at
		// all. A zone names a local interface, not a different host.
		Name:       "an IPv6 zone does not carry a target out of an exclusion",
		Target:     "fe80::1%eth0",
		Allowed:    []string{"fe80::/10"},
		Exclusions: []string{"fe80::1"},
		Want:       false,
	},
	{
		Name:       "and not out of a CIDR exclusion either",
		Target:     "fe80::1%eth0",
		Allowed:    []string{"fe80::/10"},
		Exclusions: []string{"fe80::/64"},
		Want:       false,
	},
	{
		// The root label is syntax, not a different name.
		Name:       "a trailing dot does not defeat a hostname exclusion",
		Target:     "printer.corp.example.",
		Allowed:    []string{"corp.example", "printer.corp.example"},
		Exclusions: []string{"printer.corp.example"},
		Want:       false,
	},
	{
		Name:    "and a trailing dot in the RULE still matches",
		Target:  "printer.corp.example",
		Allowed: []string{"printer.corp.example."},
		Want:    true,
	},
	{
		Name:    "an IPv6 target inside an IPv6 allow",
		Target:  "2001:db8::5",
		Allowed: []string{"2001:db8::/32"},
		Want:    true,
	},
	{
		Name:    "an IPv6 target outside every allow",
		Target:  "2001:db8::5",
		Allowed: []string{"192.0.2.0/24"},
		Want:    false,
	},
}
