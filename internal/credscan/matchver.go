package credscan

import "sort"

// BuildServiceVersion pairs one identified service (its product and banner-extracted
// version) with the installed version of that product's package, for the
// version-extraction measurement (requirement 3, measurement 1).
//
// candidates is the product's source packages (product_packages, ADR-064's map);
// installed maps source package -> installed version (the SSH inventory). The rule:
//   - a product with no installed candidate yields an empty InstalledVersion, which
//     ClassifyVersion reads as "wrong" — the banner claimed a version for a package
//     not present;
//   - where the product maps to several installed candidates, the banner is judged
//     against each and the reported InstalledVersion is the one it is consistent with
//     (so a correct banner is not marked wrong because another package of the same
//     product has a different version); absent a consistent one, the first installed
//     candidate in sorted order is reported, and ClassifyVersion will mark it wrong.
//
// This correspondence rule is the version measurement's ONE heuristic, and its review
// trigger (ADR-076): the finding-accuracy measurement (Diff) has none — it compares
// exact credentialed truth against the stored findings and needs no product map.
func BuildServiceVersion(service, product, banner string, candidates []string, installed map[string]string) ServiceVersion {
	sv := ServiceVersion{Service: service, Product: product, BannerVersion: banner}

	sorted := append([]string(nil), candidates...)
	sort.Strings(sorted)

	var firstInstalled string
	firstFound := false
	for _, pkg := range sorted {
		iv, ok := installed[pkg]
		if !ok {
			continue // this candidate package is not installed on the host
		}
		if !firstFound {
			firstInstalled, sv.SourcePackage, firstFound = iv, pkg, true
		}
		if banner != "" && versionConsistent(banner, iv) {
			sv.SourcePackage = pkg
			sv.InstalledVersion = iv
			return sv // a consistent installed candidate is the match
		}
	}
	if firstFound {
		sv.InstalledVersion = firstInstalled // installed, but not consistent -> wrong
	}
	return sv
}
