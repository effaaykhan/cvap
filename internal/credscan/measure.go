package credscan

import (
	"sort"
	"strconv"
	"strings"
)

// The three measurements ADR-075/076 make the deliverable. All pure: the command
// gathers the inputs (unauthenticated findings from the pipeline, installed
// packages over SSH, credentialed-truth findings from the keyspace) and these
// compute the verdicts. Nothing here is tuned to a sample (deliverable 4) — these
// only compare.

// --- 1. Version extraction: banner version vs installed, per service ----------

// VersionVerdict is the three buckets requirement 3 asks for.
type VersionVerdict string

const (
	VersionRight  VersionVerdict = "right"  // banner version consistent with installed
	VersionWrong  VersionVerdict = "wrong"  // banner version present but inconsistent
	VersionAbsent VersionVerdict = "absent" // banner produced no version to check
)

// ServiceVersion is one identified service's banner version and the installed
// version of the package it maps to.
type ServiceVersion struct {
	Service          string
	Product          string
	SourcePackage    string // the package the product maps to (ADR-064), or "" if unmapped
	BannerVersion    string // what the unauthenticated scan extracted ("" = absent)
	InstalledVersion string // what the package manager reports ("" = package not installed)
	Verdict          VersionVerdict
}

// versionConsistent is the "did the banner get the version right" test — NOT the
// vulnerability comparator. A banner commonly reports a truncated-but-correct
// version (upstream without the Debian revision: "5.0.51a" for "5.0.51a-3ubuntu5"),
// which is right for extraction purposes; an exact match is right; anything else
// with a banner version present is wrong.
func versionConsistent(banner, installed string) bool {
	if banner == "" || installed == "" {
		return false
	}
	// Strip the dpkg epoch from BOTH sides first. A banner reports the upstream
	// version with no packaging epoch ("10.2p1"), while dpkg carries one
	// ("1:10.2p1-2ubuntu3.5"). Without removing it the upstream-prefix test below
	// fails on the leading "1:" and a correct banner is judged WRONG — found on a
	// real Ubuntu 26.04 host reading openssh (S39), and fixed before that host's
	// version-extraction number was taken, because a comparator bug must not be
	// carried through the comparator measurement it would corrupt.
	banner, installed = stripEpoch(banner), stripEpoch(installed)
	if banner == installed {
		return true
	}
	// banner is a leading component of the installed version (upstream prefix).
	return strings.HasPrefix(installed, banner)
}

// stripEpoch removes a leading dpkg epoch ("N:") from a version string. The epoch is
// one or more digits before the first colon; anything else (no colon, or a
// non-numeric prefix) is left untouched.
func stripEpoch(v string) string {
	if i := strings.IndexByte(v, ':'); i > 0 {
		if _, err := strconv.Atoi(v[:i]); err == nil {
			return v[i+1:]
		}
	}
	return v
}

// ClassifyVersion fills each ServiceVersion's Verdict. absent when the banner gave
// no version; right when consistent with the installed version; wrong otherwise
// (including the banner claiming a version for a package that is not installed).
func ClassifyVersion(svcs []ServiceVersion) []ServiceVersion {
	out := make([]ServiceVersion, len(svcs))
	for i, s := range svcs {
		switch {
		case s.BannerVersion == "":
			s.Verdict = VersionAbsent
		case versionConsistent(s.BannerVersion, s.InstalledVersion):
			s.Verdict = VersionRight
		default:
			s.Verdict = VersionWrong
		}
		out[i] = s
	}
	return out
}

// VersionTally counts the buckets for the headline line.
type VersionTally struct{ Right, Wrong, Absent int }

func TallyVersions(svcs []ServiceVersion) VersionTally {
	var t VersionTally
	for _, s := range svcs {
		switch s.Verdict {
		case VersionRight:
			t.Right++
		case VersionWrong:
			t.Wrong++
		case VersionAbsent:
			t.Absent++
		}
	}
	return t
}

// --- 2. Release attribution: band vote vs /etc/os-release ---------------------

type ReleaseVerdict string

const (
	ReleaseMatch      ReleaseVerdict = "match"      // band vote == os-release codename
	ReleaseMismatch   ReleaseVerdict = "mismatch"   // both present, differ
	ReleaseUnresolved ReleaseVerdict = "unresolved" // band vote produced nothing
)

// CompareRelease judges what band resolution concluded against the exact codename.
func CompareRelease(bandResolved, osReleaseCodename string) ReleaseVerdict {
	if bandResolved == "" {
		return ReleaseUnresolved
	}
	if bandResolved == osReleaseCodename {
		return ReleaseMatch
	}
	return ReleaseMismatch
}

// --- 3. Finding accuracy: FP/FN of unauthenticated vs credentialed truth -------

// FindingKey is a finding's identity for comparison: the source package and the
// CVE, on one host. Package-plus-CVE, not CVE alone, so two packages with the
// same CVE are two findings (matching the ADR-070 dedup shape).
type FindingKey struct {
	Package string
	CVE     string
}

func (k FindingKey) norm() FindingKey {
	return FindingKey{Package: strings.ToLower(k.Package), CVE: strings.ToUpper(k.CVE)}
}

// Accuracy is the §6.2 result on a real host.
type Accuracy struct {
	TruePositive  []FindingKey // in both — unauthenticated got it right
	FalsePositive []FindingKey // unauthenticated claimed it; credentialed truth does not have it
	FalseNegative []FindingKey // credentialed truth has it; unauthenticated missed it
}

// Diff computes TP/FP/FN of the unauthenticated finding set against credentialed
// ground truth. This is the measurement the session exists for; it is a set
// comparison and nothing more — it does not decide which side is "correct" beyond
// the definition (truth is the credentialed read).
func Diff(unauth, truth []FindingKey) Accuracy {
	inTruth := map[FindingKey]bool{}
	for _, k := range truth {
		inTruth[k.norm()] = true
	}
	inUnauth := map[FindingKey]bool{}
	for _, k := range unauth {
		inUnauth[k.norm()] = true
	}
	var a Accuracy
	for k := range inUnauth {
		if inTruth[k] {
			a.TruePositive = append(a.TruePositive, k)
		} else {
			a.FalsePositive = append(a.FalsePositive, k)
		}
	}
	for k := range inTruth {
		if !inUnauth[k] {
			a.FalseNegative = append(a.FalseNegative, k)
		}
	}
	sortKeys(a.TruePositive)
	sortKeys(a.FalsePositive)
	sortKeys(a.FalseNegative)
	return a
}

func sortKeys(ks []FindingKey) {
	sort.Slice(ks, func(i, j int) bool {
		if ks[i].Package != ks[j].Package {
			return ks[i].Package < ks[j].Package
		}
		return ks[i].CVE < ks[j].CVE
	})
}
