package domain

import "testing"

func approxEq(a, b float32) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < 1e-4
}

func TestUpstreamBand(t *testing.T) {
	cases := map[string]string{
		"1:4.7p1-8ubuntu1.2":      "4.7p1",   // epoch + revision stripped
		"5.0.51a-3ubuntu5":        "5.0.51a", // revision stripped, letter kept
		"5.0.51a-3ubuntu5.4":      "5.0.51a",
		"4.7p1":                   "4.7p1", // no epoch, no revision
		"2:3.4.7~dfsg-1ubuntu3.2": "3.4.7~dfsg",
		"2.2.8-1ubuntu0.22":       "2.2.8",
		"  2.2.8-1ubuntu0.22  ":   "2.2.8",
		"":                        "",
	}
	for in, want := range cases {
		if got := UpstreamBand(in); got != want {
			t.Errorf("UpstreamBand(%q) = %q, want %q", in, got, want)
		}
	}
}

// The acceptance shape in miniature: three services band-match hardy and agree,
// two abstain (one no-analogue, one band-mismatch). Resolved to hardy, and the
// abstentions are VISIBLE in the provenance rather than silently absent.
func TestResolveRelease_ThreeAgreeTwoAbstain(t *testing.T) {
	res := ResolveRelease([]ReleaseVote{
		{Service: "ssh", Port: 22, Product: "OpenSSH", Band: "4.7p1", Candidates: []string{"hardy"}, HasAnalogue: true},
		{Service: "mysql", Port: 3306, Product: "MySQL", Band: "5.0.51a", Candidates: []string{"hardy"}, HasAnalogue: true},
		{Service: "http", Port: 80, Product: "Apache", Band: "2.2.8", Candidates: []string{"hardy"}, HasAnalogue: true},
		{Service: "smb", Port: 445, Product: "Samba", Band: "3.0.20", Candidates: nil, HasAnalogue: true},  // band matched nothing
		{Service: "ftp", Port: 21, Product: "ProFTPD", Band: "1.3.1", Candidates: nil, HasAnalogue: false}, // no analogue
	})
	if res.Release == nil || *res.Release != "hardy" {
		t.Fatalf("release = %v, want hardy", res.Release)
	}
	if !approxEq(res.Confidence, 0.90) {
		t.Errorf("confidence = %v, want 0.90 (3 agreeing, unanimous)", res.Confidence)
	}
	roles := map[string]ReleaseRole{}
	reasons := map[string]string{}
	for _, s := range res.Provenance {
		roles[s.Product] = s.Role
		reasons[s.Product] = s.Reason
	}
	if roles["OpenSSH"] != ReleaseContributed || roles["MySQL"] != ReleaseContributed || roles["Apache"] != ReleaseContributed {
		t.Errorf("the three agreeing services must be 'contributed': %+v", roles)
	}
	if roles["Samba"] != ReleaseAbstained || reasons["Samba"] == "" {
		t.Errorf("Samba (band matched nothing) must abstain with a reason: role=%q reason=%q", roles["Samba"], reasons["Samba"])
	}
	if roles["ProFTPD"] != ReleaseAbstained || reasons["ProFTPD"] == "" {
		t.Errorf("ProFTPD (no analogue) must abstain with a reason: role=%q reason=%q", roles["ProFTPD"], reasons["ProFTPD"])
	}
	// The two abstentions carry DIFFERENT reasons — no-analogue vs band-mismatch.
	if reasons["Samba"] == reasons["ProFTPD"] {
		t.Errorf("the two abstention reasons must differ (band-mismatch vs no-analogue), both were %q", reasons["Samba"])
	}
}

// A single clean vote that narrows to exactly one release now RESOLVES at reduced
// confidence (ADR-080, superseding ADR-066): a unique determination is not the weak
// case the threshold guarded against, and abstaining produced silence that reads as
// clean.
func TestResolveRelease_SingleUniqueVoteResolves(t *testing.T) {
	res := ResolveRelease([]ReleaseVote{
		{Service: "ssh", Port: 22, Product: "OpenSSH", Band: "4.7p1", Candidates: []string{"hardy"}, HasAnalogue: true},
		{Service: "ftp", Port: 21, Product: "vsftpd", Band: "2.3.4", Candidates: nil, HasAnalogue: true},
	})
	if res.Release == nil || *res.Release != "hardy" {
		t.Fatalf("release = %v, want hardy (a single unique vote resolves under ADR-080)", res.Release)
	}
	if !approxEq(res.Confidence, 0.60) {
		t.Errorf("confidence = %v, want 0.60 (single unique vote, reduced/uncorroborated)", res.Confidence)
	}
	var sawContributed bool
	for _, s := range res.Provenance {
		if s.Product == "OpenSSH" && s.Role == ReleaseContributed {
			sawContributed = true
		}
	}
	if !sawContributed {
		t.Errorf("the single hardy vote should be recorded as contributed")
	}
}

// The case the threshold still guards: a single AMBIGUOUS vote (several candidates)
// is not a clean vote and still abstains — unchanged by ADR-080.
func TestResolveRelease_SingleAmbiguousVoteAbstains(t *testing.T) {
	res := ResolveRelease([]ReleaseVote{
		{Service: "ssh", Port: 22, Product: "OpenSSH", Band: "4.7p1", Candidates: []string{"hardy", "lucid"}, HasAnalogue: true},
	})
	if res.Release != nil {
		t.Fatalf("release = %v, want nil (a single vote consistent with several releases must still abstain)", *res.Release)
	}
}

// Two clean votes for the same release cross the threshold.
func TestResolveRelease_TwoAgreeResolves(t *testing.T) {
	res := ResolveRelease([]ReleaseVote{
		{Service: "ssh", Product: "OpenSSH", Band: "4.7p1", Candidates: []string{"hardy"}, HasAnalogue: true},
		{Service: "http", Product: "Apache", Band: "2.2.8", Candidates: []string{"hardy"}, HasAnalogue: true},
	})
	if res.Release == nil || *res.Release != "hardy" {
		t.Fatalf("release = %v, want hardy (two agreeing meets the threshold)", res.Release)
	}
}

// A split does not resolve: two for hardy, two for lucid is a tie, family-only.
func TestResolveRelease_SplitDoesNotResolve(t *testing.T) {
	res := ResolveRelease([]ReleaseVote{
		{Service: "ssh", Product: "OpenSSH", Band: "4.7p1", Candidates: []string{"hardy"}, HasAnalogue: true},
		{Service: "http", Product: "Apache", Band: "2.2.8", Candidates: []string{"hardy"}, HasAnalogue: true},
		{Service: "smtp", Product: "Postfix", Band: "2.7.0", Candidates: []string{"lucid"}, HasAnalogue: true},
		{Service: "ftp", Product: "vsftpd", Band: "2.2.2", Candidates: []string{"lucid"}, HasAnalogue: true},
	})
	if res.Release != nil {
		t.Fatalf("release = %v, want nil (2-2 tie must not resolve)", *res.Release)
	}
}

// A clear plurality resolves even with a dissenter, which is recorded as ignored.
func TestResolveRelease_PluralityWithDissent(t *testing.T) {
	res := ResolveRelease([]ReleaseVote{
		{Service: "ssh", Product: "OpenSSH", Band: "4.7p1", Candidates: []string{"hardy"}, HasAnalogue: true},
		{Service: "http", Product: "Apache", Band: "2.2.8", Candidates: []string{"hardy"}, HasAnalogue: true},
		{Service: "smtp", Product: "Postfix", Band: "2.5.1", Candidates: []string{"hardy"}, HasAnalogue: true},
		{Service: "ftp", Product: "vsftpd", Band: "2.2.2", Candidates: []string{"lucid"}, HasAnalogue: true},
	})
	if res.Release == nil || *res.Release != "hardy" {
		t.Fatalf("release = %v, want hardy (3 vs 1)", res.Release)
	}
	if !approxEq(res.Confidence, 0.675) {
		t.Errorf("confidence = %v, want 0.675 (3-vote base 0.90 scaled by 3/4 for the dissenter)", res.Confidence)
	}
	var dissent ReleaseRole
	for _, s := range res.Provenance {
		if s.Product == "vsftpd" {
			dissent = s.Role
		}
	}
	if dissent != ReleaseIgnored {
		t.Errorf("the lucid dissenter must be 'ignored', got %q", dissent)
	}
}

// A band collision (apache2 2.2.22 across precise and quantal) is a multi-candidate
// vote: it corroborates the leader if the leader is in its set (agreed), but it
// never pins on its own. Here the collision alone, with no clean vote, resolves
// nothing.
func TestResolveRelease_CollisionAloneDoesNotPin(t *testing.T) {
	res := ResolveRelease([]ReleaseVote{
		{Service: "http", Product: "Apache", Band: "2.2.22", Candidates: []string{"precise", "quantal"}, HasAnalogue: true},
	})
	if res.Release != nil {
		t.Fatalf("release = %v, want nil (a collision is not a clean vote)", *res.Release)
	}
	if len(res.Provenance) != 1 || res.Provenance[0].Role == ReleaseContributed {
		t.Errorf("a lone collision must not read as contributed: %+v", res.Provenance)
	}
}

// A collision corroborates a clean leader it contains: two clean hardy... no —
// use a case where the collision's set contains the resolved leader.
func TestResolveRelease_CollisionAgreesWithLeader(t *testing.T) {
	res := ResolveRelease([]ReleaseVote{
		{Service: "ssh", Product: "OpenSSH", Band: "3.4.7", Candidates: []string{"precise"}, HasAnalogue: true},
		{Service: "smtp", Product: "Postfix", Band: "2.2.22", Candidates: []string{"precise"}, HasAnalogue: true},
		{Service: "http", Product: "Apache", Band: "2.2.22", Candidates: []string{"precise", "quantal"}, HasAnalogue: true},
	})
	if res.Release == nil || *res.Release != "precise" {
		t.Fatalf("release = %v, want precise (two clean votes)", res.Release)
	}
	var apacheRole ReleaseRole
	for _, s := range res.Provenance {
		if s.Product == "Apache" {
			apacheRole = s.Role
		}
	}
	if apacheRole != ReleaseAgreed {
		t.Errorf("the precise|quantal collision should 'agree' with the precise leader, got %q", apacheRole)
	}
}

// A service identified to a product but carrying no version abstains VISIBLY,
// with a reason distinct from a band mismatch — it was seen, it just could not
// contribute (ADR-064: absence must be visible, not dropped).
func TestResolveRelease_VersionlessAbstainsVisibly(t *testing.T) {
	res := ResolveRelease([]ReleaseVote{
		{Service: "ssh", Product: "OpenSSH", Band: "4.7p1", Candidates: []string{"hardy"}, HasAnalogue: true},
		{Service: "http", Product: "Apache", Band: "2.2.8", Candidates: []string{"hardy"}, HasAnalogue: true},
		{Service: "smtp", Product: "Postfix", Band: "", Candidates: nil, HasAnalogue: true}, // product, no version
	})
	if res.Release == nil || *res.Release != "hardy" {
		t.Fatalf("release = %v, want hardy", res.Release)
	}
	var postfix ReleaseSource
	for _, s := range res.Provenance {
		if s.Product == "Postfix" {
			postfix = s
		}
	}
	if postfix.Role != ReleaseAbstained {
		t.Fatalf("versionless Postfix should abstain, got %q", postfix.Role)
	}
	if postfix.Reason == "" || postfix.Reason == "observed version matches no release's band" {
		t.Errorf("versionless abstention needs its own reason (not the band-mismatch one), got %q", postfix.Reason)
	}
}

// Confidence distinguishes a two-vote resolution from a three- and four-vote one,
// and a unanimous pair outranks a disputed plurality (ADR-064) — both resolve,
// but the finding pipeline must be able to tell them apart later.
func TestResolveRelease_ConfidenceGrowsWithAgreement(t *testing.T) {
	vote := func(svc, band string) ReleaseVote {
		return ReleaseVote{Service: svc, Product: svc, Band: band, Candidates: []string{"hardy"}, HasAnalogue: true}
	}
	two := ResolveRelease([]ReleaseVote{vote("a", "1"), vote("b", "2")})
	three := ResolveRelease([]ReleaseVote{vote("a", "1"), vote("b", "2"), vote("c", "3")})
	four := ResolveRelease([]ReleaseVote{vote("a", "1"), vote("b", "2"), vote("c", "3"), vote("d", "4")})
	if !(two.Confidence < three.Confidence && three.Confidence < four.Confidence) {
		t.Errorf("confidence must grow with agreement: 2=%v 3=%v 4=%v", two.Confidence, three.Confidence, four.Confidence)
	}
	// A unanimous pair (2/2 = 0.80) beats a disputed plurality (3/5, 0.90*3/5=0.54).
	disputed := ResolveRelease([]ReleaseVote{
		vote("a", "1"), vote("b", "2"), vote("c", "3"),
		{Service: "d", Product: "d", Band: "9", Candidates: []string{"lucid"}, HasAnalogue: true},
		{Service: "e", Product: "e", Band: "9", Candidates: []string{"lucid"}, HasAnalogue: true},
	})
	if disputed.Release == nil || *disputed.Release != "hardy" {
		t.Fatalf("3 vs 2 should resolve hardy, got %v", disputed.Release)
	}
	if !(two.Confidence > disputed.Confidence) {
		t.Errorf("a unanimous pair (%v) should outrank a disputed 3/5 (%v)", two.Confidence, disputed.Confidence)
	}
}

// No votes at all -> unresolved, empty provenance is fine.
func TestResolveRelease_NoVotes(t *testing.T) {
	res := ResolveRelease(nil)
	if res.Release != nil {
		t.Fatalf("release = %v, want nil for no votes", *res.Release)
	}
}
