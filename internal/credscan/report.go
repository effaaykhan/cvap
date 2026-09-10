package credscan

import (
	"fmt"
	"sort"
	"strings"
)

// Report is the deliverable (ADR-075/076): the three measurements on one real host,
// assembled and rendered. It is pure — the command gathers the inputs (SSH read,
// unauthenticated findings, credentialed truth) and hands them here — so the whole
// output is fixture-testable without a host.
type Report struct {
	Host     string
	Release  OSRelease
	Packages int // installed packages read

	// 1. Version extraction: banner version vs installed, per service.
	Versions []ServiceVersion

	// 2. Release attribution: what unauthenticated band resolution concluded, and
	// what /etc/os-release actually says.
	BandResolved   string // band vote's codename ("" = unresolved)
	ReleaseVerdict ReleaseVerdict

	// 3. Finding accuracy: unauthenticated findings vs credentialed truth.
	Accuracy     Accuracy
	TruthSkipped []string // fixes the truth could not judge (stated, not hidden)
}

// Render produces the plain-text measurement report. It leads with the three
// headline numbers, then the actionable detail (which services' versions were
// wrong, which findings were false positives, which were missed), then the standing
// caveat: nothing here is tuned against this sample this session — a banner-inference
// error is a backlog finding, not a fix (§5.5, ADR-076 deliverable 4).
func (r Report) Render() string {
	var b strings.Builder
	tally := TallyVersions(r.Versions)

	fmt.Fprintf(&b, "Credentialed validation measurement — %s\n", r.Host)
	fmt.Fprintf(&b, "  release (read):  %s %s (%s)\n", r.Release.ID, r.Release.VersionID, r.Release.Codename)
	fmt.Fprintf(&b, "  packages read:   %d\n", r.Packages)
	b.WriteString("\n")

	// --- 1. Version extraction (one line per service) ---
	fmt.Fprintf(&b, "1. Version extraction (banner vs installed, %d services)\n", len(r.Versions))
	fmt.Fprintf(&b, "   totals: RIGHT %d   WRONG %d   ABSENT %d\n", tally.Right, tally.Wrong, tally.Absent)
	for _, s := range r.Versions {
		banner, installed := s.BannerVersion, s.InstalledVersion
		if banner == "" {
			banner = "-"
		}
		if installed == "" {
			installed = "-"
		}
		fmt.Fprintf(&b, "   %-16s banner %-28s installed %-28s %s\n",
			s.Service, banner, installed, verdictWord(s.Verdict))
	}
	b.WriteString("\n")

	// --- 2. Release attribution ---
	b.WriteString("2. Release attribution (band vote vs /etc/os-release)\n")
	band := r.BandResolved
	if band == "" {
		band = "(unresolved)"
	}
	fmt.Fprintf(&b, "   band vote %q  vs  os-release %q  ->  %s\n",
		band, r.Release.Codename, r.ReleaseVerdict)
	b.WriteString("\n")

	// --- 3. Finding accuracy (the number this session exists for) ---
	tp := len(r.Accuracy.TruePositive)
	fp := len(r.Accuracy.FalsePositive)
	fn := len(r.Accuracy.FalseNegative)
	unauthTotal := tp + fp // everything the unauthenticated scan claimed
	truthTotal := tp + fn  // everything the credentialed truth holds
	b.WriteString("3. Finding accuracy (unauthenticated vs credentialed truth)\n")
	fmt.Fprintf(&b, "   TP %d   FP %d   FN %d\n", tp, fp, fn)
	fmt.Fprintf(&b, "   FP rate: %d / %d = %s of unauthenticated findings were false positives\n",
		fp, unauthTotal, pct(fp, unauthTotal))
	fmt.Fprintf(&b, "   FN rate: %d / %d = %s of credentialed-truth findings were missed\n",
		fn, truthTotal, pct(fn, truthTotal))
	fmt.Fprintf(&b, "   precision %s (TP/%d)   recall %s (TP/%d)\n",
		pct(tp, unauthTotal), unauthTotal, pct(tp, truthTotal), truthTotal)
	writeKeys(&b, "   FP (claimed, not in truth)", r.Accuracy.FalsePositive)
	writeKeys(&b, "   FN (in truth, missed)     ", r.Accuracy.FalseNegative)
	if len(r.TruthSkipped) > 0 {
		fmt.Fprintf(&b, "   truth could not judge %d candidate fix(es):\n", len(r.TruthSkipped))
		skipped := append([]string(nil), r.TruthSkipped...)
		sort.Strings(skipped)
		for _, s := range skipped {
			fmt.Fprintf(&b, "     - %s\n", s)
		}
	}
	b.WriteString("\n")

	b.WriteString("Nothing above is tuned against this sample this session: a banner-inference\n")
	b.WriteString("error is a backlog finding, not a fix (§5.5, ADR-076).\n")
	return b.String()
}

// pct formats n/d as a percentage, stating "n/a" when the denominator is zero
// rather than dividing — an empty denominator is "nothing to be right or wrong
// about", not 0%.
func pct(n, d int) string {
	if d == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.1f%%", 100*float64(n)/float64(d))
}

func verdictWord(v VersionVerdict) string {
	switch v {
	case VersionRight:
		return "RIGHT"
	case VersionWrong:
		return "WRONG"
	default:
		return "ABSENT"
	}
}

func writeKeys(b *strings.Builder, label string, ks []FindingKey) {
	if len(ks) == 0 {
		return
	}
	fmt.Fprintf(b, "%s:\n", label)
	for _, k := range ks {
		fmt.Fprintf(b, "     - %s  %s\n", k.Package, k.CVE)
	}
}
