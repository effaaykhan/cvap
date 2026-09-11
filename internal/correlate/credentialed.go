package correlate

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/store"
	"github.com/effaaykhan/cvap/internal/version"
)

// evaluateCredentialed consumes a credentialed-host engine's `package` observation —
// exact installed inventory and exact release, read over SSH — and does what
// unauthenticated inference cannot (ADR-077/078/087/088):
//
//   - it matches each installed package's EXACT version against the advisory keyspace
//     with the release's own comparator (no product->package map, no banner-version
//     guess), so revision blindness (ADR-078) is gone; and
//   - it RESOLVES the inferred findings the read now speaks to: a credentialed match
//     supersedes the inferred finding for the same (package, cve); a credentialed
//     non-match refutes it.
//
// This is the last link of the fleet credentialed path, and the one that closes the
// sixteen inferred OpenSSH findings on a fully-patched host as refuted_by_credentialed
// (ADR-088's acceptance). It runs in resolveHost's transaction, after the release is
// written by deriveRelease (whose dormant ADR-077 rule the same observation fires).
func (c *Correlator) evaluateCredentialed(ctx context.Context, conn *store.Conn, assetID uuid.UUID, h host, now time.Time) error {
	cred := credentialedInventory(h)
	if cred == nil {
		return nil // no credentialed inventory for this host; nothing to adjudicate
	}
	if c.advisoryRuleID == uuid.Nil {
		return nil // no advisory rule seeded; matching disabled (same guard as evaluateAdvisories)
	}

	// The exact-version vulnerable set, and the packages the read covers (so we only
	// adjudicate inferred findings the credentialed read can actually speak to).
	credVulnerable := map[store.AdvisoryKey]store.AdvisoryVuln{}
	covered := map[string]bool{}
	adv := store.Advisories{}
	for _, pkg := range cred.Installed {
		covered[pkg.Name] = true
		fixes, err := adv.FixesFor(ctx, conn, cred.Release, pkg.Name)
		if err != nil {
			return err
		}
		for _, fix := range fixes {
			if fix.FixedVersion == "" {
				continue // an empty fix would open the range against every version (ADR-070)
			}
			scheme, ok := version.SchemeByName(fix.Comparator)
			if !ok {
				continue // never guess a comparator (ADR-062)
			}
			if !(version.AffectedRange{Fixed: fix.FixedVersion}).Vulnerable(scheme, pkg.Version) {
				continue // exact installed version is at or above the fix: not vulnerable
			}
			vulns, err := adv.AdvisoryVulnDefs(ctx, conn, fix.AdvisoryRef)
			if err != nil {
				return err
			}
			for _, v := range vulns {
				credVulnerable[store.AdvisoryKey{Package: pkg.Name, CVE: v.CVE}] = v
			}
		}
	}

	// Raise a credentialed finding for each confirmed (package, cve): exact match,
	// source=credentialed, confidence 1.0 (the version was read, not inferred).
	for key, v := range credVulnerable {
		if _, _, err := (store.Findings{}).Upsert(ctx, conn, store.Finding{
			AssetID:    assetID,
			RuleID:     c.advisoryRuleID,
			DedupKey:   fmt.Sprintf("credentialed|%s|%s|%s", assetID, key.Package, key.CVE),
			Locator:    key.Package,
			Severity:   severityFromCVSS(v.CVSSBase),
			Confidence: 1.0,
			Source:     "credentialed",
			VulnDefID:  v.VulnDefID,
		}, now); err != nil {
			return err
		}
	}

	// Supersession: every inferred advisory finding for a covered package is resolved
	// by the credentialed read — matched → superseded, unmatched → refuted.
	inferred, err := (store.Findings{}).AdvisoryFindingsForAsset(ctx, conn, assetID)
	if err != nil {
		return err
	}
	for _, f := range inferred {
		if f.Source == "credentialed" {
			continue // never supersede a credentialed finding
		}
		if !covered[f.Package] {
			continue // the read did not cover this package; leave the inferred finding standing
		}
		newStatus := "refuted_by_credentialed"
		if _, ok := credVulnerable[store.AdvisoryKey{Package: f.Package, CVE: f.CVE}]; ok {
			newStatus = "superseded_by_credentialed"
		}
		closed, err := (store.Findings{}).Supersede(ctx, conn, f.ID, newStatus, now)
		if err != nil {
			return err
		}
		if closed {
			if err := (store.Findings{}).RecordTransition(ctx, conn, f.ID, f.Status, newStatus,
				"credentialed read resolved an inferred finding: "+newStatus, now); err != nil {
				return err
			}
		}
	}
	return nil
}

// credentialedInventory returns the credentialed-host engine's package observation
// for this host — the one carrying an exact, os-release-read inventory — or nil.
func credentialedInventory(h host) *packagePayload {
	for _, o := range h.obs {
		if o.Type != store.ObsPackage {
			continue
		}
		var p packagePayload
		if err := json.Unmarshal(o.Payload, &p); err != nil {
			continue
		}
		if p.ReleaseSource == "os-release" && len(p.Installed) > 0 {
			return &p
		}
	}
	return nil
}
