package credscan

import "github.com/effaaykhan/cvap/internal/version"

// The credentialed ground truth: the advisory finding set computed from the EXACT
// installed inventory and the EXACT release, which is what §6.2 measures the
// unauthenticated findings against. It is stronger than the unauthenticated path
// (internal/correlate.evaluateAdvisories) by construction, not by tuning:
//
//   - no product->package map (ADR-064): the installed package IS the source
//     package, read from dpkg-query, not inferred from a banner;
//   - no band resolution (ADR-064/065): the release is /etc/os-release, read;
//   - the version is the installed version, exact — not banner-extracted.
//
// The comparator authority is unchanged (ADR-062: Go decides the version relation),
// and the two refusals evaluateAdvisories makes are made here identically, so the
// truth is computed by the same rules as the thing it judges — only the inputs are
// better.

// AdvisoryFix is one advisory fix as the truth computation consumes it: the three
// fields evaluateAdvisories reads from store.AdvisoryFix, redeclared here so this
// package stays free of the store (and its database dependency) and the truth
// computation is fixture-testable. The command adapts store.AdvisoryFix into this.
type AdvisoryFix struct {
	AdvisoryRef  string
	FixedVersion string
	Comparator   string // "dpkg" | "rpm" (version_comparator enum)
}

// FixLookup returns every advisory fix for a source package on a release — the
// candidate set (store.Advisories.FixesFor, injected). VulnLookup returns the CVE
// ids an advisory covers (store.Advisories.AdvisoryVulnDefs, injected). Both are
// injected so CredentialedTruth is pure and host-independent: the command wires the
// real store reads, a test wires fixtures.
type (
	FixLookup  func(release, sourcePkg string) ([]AdvisoryFix, error)
	VulnLookup func(advisoryRef string) ([]string, error)
)

// TruthResult is the credentialed ground truth plus what it could not judge.
type TruthResult struct {
	Keys    []FindingKey // the ground-truth (package, cve) finding set
	Skipped []string     // human-readable reasons a candidate fix was not judged
}

// CredentialedTruth computes the ground-truth advisory finding set from the exact
// installed packages and the exact release codename. Same comparator authority and
// same two refusals as evaluateAdvisories: an empty fixed_version is skipped rather
// than allowed to open the affected range against every installed version (ADR-070),
// and an unknown comparator is skipped, never defaulted, because a dpkg version
// judged by rpm rules is silently wrong (ADR-062). A skip is recorded in Skipped so
// the measurement states what it could not judge rather than under-report in
// silence — a corrupted ground truth would make the FP/FN number a lie, which is the
// one thing this instrument must not produce.
func CredentialedTruth(pkgs []Package, release string, fixes FixLookup, vulns VulnLookup) (TruthResult, error) {
	seen := map[FindingKey]bool{}
	var res TruthResult
	for _, p := range pkgs {
		fs, err := fixes(release, p.Source)
		if err != nil {
			return TruthResult{}, err
		}
		for _, f := range fs {
			if f.FixedVersion == "" {
				res.Skipped = append(res.Skipped,
					"empty fixed_version, "+f.AdvisoryRef+" / "+p.Source)
				continue
			}
			scheme, ok := version.SchemeByName(f.Comparator)
			if !ok {
				res.Skipped = append(res.Skipped,
					"unknown comparator "+f.Comparator+", "+f.AdvisoryRef+" / "+p.Source)
				continue
			}
			if !(version.AffectedRange{Fixed: f.FixedVersion}).Vulnerable(scheme, p.Version) {
				continue // installed version is at or above the fix: not affected
			}
			cves, err := vulns(f.AdvisoryRef)
			if err != nil {
				return TruthResult{}, err
			}
			for _, cve := range cves {
				k := (FindingKey{Package: p.Source, CVE: cve}).norm()
				if seen[k] {
					continue // one advisory can fix a CVE for a package once
				}
				seen[k] = true
				res.Keys = append(res.Keys, k)
			}
		}
	}
	sortKeys(res.Keys)
	return res, nil
}
