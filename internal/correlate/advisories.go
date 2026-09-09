package correlate

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/store"
	"github.com/effaaykhan/cvap/internal/version"
)

// evaluateAdvisories is P3.3's last link (ADR-070): a resolved release plus a
// service's banner version, matched against the advisory keyspace, becomes a
// finding carrying the CVE it matched. Runs in resolveHost's transaction, after
// the release is written, so a finding never references a release that rolled back.
//
// Gather in the store, decide in Go (ADR-062: SQL narrows, the version verdict is
// Go-authoritative). For each identified service with a version, map the product
// to its candidate packages, read each package's fixes for the resolved release,
// and where the installed version is at or below a fix, raise one finding per CVE
// the advisory covers — dedup on (asset, package, cve), NOT the port (ADR-070):
// the claim is about the package, so the same package behind two ports is one
// finding, exposed from the union of the zones it answered on.
//
// Absence is not evidence, throughout: a service with no version is not matched at
// all (B28 — absence of a version, not of risk), and a package a release never
// carried returns no fix (B30 — no advisory among advised packages, not safety).
func (c *Correlator) evaluateAdvisories(ctx context.Context, conn *store.Conn, assetID uuid.UUID, release string, releaseConf float64, h host, now time.Time) error {
	type match struct {
		pkg         string
		vuln        store.AdvisoryVuln
		advisoryRef string
		fixed       string
		comparator  string
		product     string
		installed   string
		zones       []uuid.UUID
		obsID       uuid.UUID
		observedAt  time.Time
	}
	matches := map[string]*match{}

	for _, so := range serviceObservations(h) {
		if so.Product == "" || so.Version == "" {
			continue // B28: no product+version, no match attempted — absence of a version
		}
		packages, err := (store.Advisories{}).PackagesForProduct(ctx, conn, so.Product)
		if err != nil {
			return err
		}
		for _, pkg := range packages {
			fixes, err := (store.Advisories{}).FixesFor(ctx, conn, release, pkg)
			if err != nil {
				return err
			}
			for _, fix := range fixes {
				if fix.FixedVersion == "" {
					// You cannot judge "below" a version that does not exist. An empty
					// Fixed makes AffectedRange.Vulnerable true for EVERY installed
					// version (it reads as "never fixed"), so one malformed keyspace row
					// would raise a false CVE against every host on this package — a
					// fleet-wide false positive, and a false finding loses the customer.
					// Skip it rather than let the sentinel open the range.
					c.log.WarnContext(ctx, "advisory fix has empty fixed_version; skipped",
						"advisory", fix.AdvisoryRef, "package", pkg, "release", release)
					continue
				}
				scheme, ok := version.SchemeByName(fix.Comparator)
				if !ok {
					// The matcher must not guess a comparator (ADR-062): an unknown
					// name is skipped, never defaulted — a dpkg version judged by rpm
					// rules is silently wrong. Rare, and surfaced.
					c.log.WarnContext(ctx, "advisory fix has unknown comparator; skipped",
						"advisory", fix.AdvisoryRef, "comparator", fix.Comparator, "package", pkg)
					continue
				}
				if !(version.AffectedRange{Fixed: fix.FixedVersion}).Vulnerable(scheme, so.Version) {
					continue // installed version is at or above the fix: not affected
				}
				vulns, err := (store.Advisories{}).AdvisoryVulnDefs(ctx, conn, fix.AdvisoryRef)
				if err != nil {
					return err
				}
				for _, v := range vulns {
					key := fmt.Sprintf("advisory|%s|%s|%s", assetID, pkg, v.CVE)
					m := matches[key]
					if m == nil {
						m = &match{
							pkg: pkg, vuln: v, advisoryRef: fix.AdvisoryRef, fixed: fix.FixedVersion,
							comparator: fix.Comparator, product: so.Product, installed: so.Version,
						}
						matches[key] = m
					}
					m.zones = appendZone(m.zones, so.ZoneID)
					m.obsID = so.ObservationID
					m.observedAt = so.ObservedAt
				}
			}
		}
	}

	for key, m := range matches {
		// The finding's confidence is the MINIMUM of its inference inputs, not a
		// constant and not their product (ADR-072). The comparator is exact (ADR-062)
		// and contributes 1.0, so it never binds. TODAY only release resolution
		// (ADR-065) carries a real sub-1.0 value; version extraction and the
		// product->package map are 1.0 pass-throughs — we have no principled sub-1.0
		// number for either, and inventing one is the guess this design refuses
		// (ADR-073). So min() is currently the release confidence alone: correct, and
		// untested as a composition until a genuinely weak input appears (B28's
		// response-shape version extraction is the expected first one). No floor: a
		// low input passes through honestly rather than being raised to look better
		// than its evidence.
		conf := minConf(releaseConf, versionExtractionConfidence, packageMapConfidence)
		id, _, err := (store.Findings{}).Upsert(ctx, conn, store.Finding{
			AssetID:  assetID,
			RuleID:   c.advisoryRuleID,
			DedupKey: key,
			// The finding is about the package, so the locator is the package name,
			// not a port — matching the package-shaped dedup (ADR-070).
			Locator:    m.pkg,
			Severity:   severityFromCVSS(m.vuln.CVSSBase),
			Confidence: conf,
			// The evidence was collected over the network (source names collection,
			// ADR-070); the package-shaped dedup and composed confidence carry the
			// "about a package, seen over the network, inferred not read" reading.
			Source:    "network",
			VulnDefID: m.vuln.VulnDefID,
		}, now)
		if err != nil {
			return err
		}
		if err := (store.Findings{}).SetExposure(ctx, conn, id, m.zones, now); err != nil {
			return err
		}
		// Everything an analyst needs to confirm the match by hand without
		// re-scanning (write-detection-rule evidence rule): the advisory, the CVE,
		// the package, the two versions the comparator judged — and the confidence
		// breakdown, so a finding shows WHICH input bound it (ADR-072/073), not just
		// the number. The 1.0 pass-throughs make the coverage visible on the finding:
		// only release is being weighed today.
		if err := (store.Findings{}).ReplaceEvidence(ctx, conn, id, []store.FindingEvidence{{
			ObservationID: m.obsID,
			Type:          "response",
			Data: map[string]any{
				"advisory":          m.advisoryRef,
				"cve":               m.vuln.CVE,
				"product":           m.product,
				"package":           m.pkg,
				"installed_version": m.installed,
				"fixed_version":     m.fixed,
				"comparator":        m.comparator,
				"confidence_inputs": map[string]any{
					"release_resolution": releaseConf,
					"version_extraction": versionExtractionConfidence,
					"package_map":        packageMapConfidence,
					"comparator":         "exact (1.0)",
					"composed":           conf,
					"rule":               "min of the inputs; version/map are 1.0 pass-throughs today (ADR-073)",
				},
			},
			CapturedAt: m.observedAt,
		}}); err != nil {
			return err
		}
	}
	return nil
}

// These two inputs are 1.0 PASS-THROUGHS today (ADR-073), not weights. We have no
// principled sub-1.0 confidence for either — a banner-extracted version and a curated
// product->package map are both plausibly less than certain, but assigning a number
// (0.60, 0.90) would be a first-value guess dressed as a measurement, the very shape
// this project keeps finding. So they contribute 1.0 and min() is currently the
// release confidence alone. This is a coverage statement, not a claim of certainty:
// the min mechanism is correct and UNTESTED as a composition, because there is no weak
// input in the tree yet to exercise it.
//
// Review trigger: the first input that carries a real sub-1.0 confidence tests min()
// as a composition rather than a pass-through. B28's service-identification work is the
// expected source — a version extracted by response-shape rather than a volunteered
// banner is exactly the weaker claim that should pull a finding's confidence down, and
// that is when versionExtractionConfidence stops being a constant.
const (
	versionExtractionConfidence = 1.0
	packageMapConfidence        = 1.0
)

// minConf returns the smallest of the confidences — the weakest-link composition
// (ADR-072/073). NO floor and no skipping: a low input passes through and lowers the
// finding honestly, because a finding that inherits 0.4 should carry 0.4 rather than be
// raised to look better than its evidence. Every value passed is a real input; an
// absent signal is passed as 1.0 (not binding), never as 0 to be guarded against.
func minConf(vals ...float64) float64 {
	m := 1.0
	for _, v := range vals {
		if v < m {
			m = v
		}
	}
	return m
}

// severityFromCVSS maps a CVE's CVSS base to the finding severity band. An
// unscored CVE (nil) falls back to the rule's default ('medium'), NOT a fabricated
// low — absence of a score is not a low value (ADR-069, carried into severity).
func severityFromCVSS(cvss *float64) string {
	if cvss == nil {
		return "medium"
	}
	switch {
	case *cvss >= 9.0:
		return "critical"
	case *cvss >= 7.0:
		return "high"
	case *cvss >= 4.0:
		return "medium"
	case *cvss > 0:
		return "low"
	default:
		return "info"
	}
}

// appendZone adds a zone to the set, skipping the nil zone and duplicates — a
// package seen on several ports in one zone is exposed from that zone once.
func appendZone(zones []uuid.UUID, z uuid.UUID) []uuid.UUID {
	if z == uuid.Nil {
		return zones
	}
	for _, existing := range zones {
		if existing == z {
			return zones
		}
	}
	return append(zones, z)
}
