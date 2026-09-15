package correlate

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/domain"
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
//
// The kernel is the one package where "installed" and "running" differ by design
// (B36, ADR-099): a Debian-family host keeps every installed ABI's packages side by
// side, so the source-collapsed inventory carries `linux` at the old ABI's version
// too, and the exact matcher read that as below every later USN — 551 false kernel
// findings on a host at the fix (ADR-093). domain.ClassifyKernelPackage reads the
// observation's `uname -r` and the binary name: a kernel package at the running
// kernel's version is matched, one at any other version is inventory and raises
// nothing, and a read with no `uname -r` judges the kernel neither way. The
// instrument's ground truth calls the same function, so the two cannot disagree.
//
// A credentialed finding is the read's own claim, so the read also withdraws it: an
// open credentialed finding for a (package, cve) this read no longer matches — the
// package upgraded, removed, or (kernel) no longer the one running — is closed as
// remediated with a transition. A credentialed read is the whole inventory, so
// absence means gone, unlike an endpoint that was merely not scanned (findings.go).
func (c *Correlator) evaluateCredentialed(ctx context.Context, conn *store.Conn, assetID uuid.UUID, h host, now time.Time) error {
	cred := credentialedInventory(h)
	if cred == nil {
		return nil // no credentialed inventory for this host; nothing to adjudicate
	}
	if c.advisoryRuleID == uuid.Nil {
		return nil // no advisory rule seeded; matching disabled (same guard as evaluateAdvisories)
	}

	// The exact-version vulnerable set, and what the read said about each source
	// package — the facts the withdrawal below is keyed on, so that "cannot say"
	// is never spelled "remediated" (the security review measured three ways it
	// was: a read with no uname, a read whose uname named no installed kernel,
	// and a release key whose keyspace had no rows for the package):
	//   present  — the read carried rows for the source at all;
	//   covered  — at least one row was JUDGED (an ordinary package, or the
	//              running kernel's own rows), so inferred findings on the
	//              source can be superseded or refuted;
	//   kernel / running — the source had kernel rows, and whether any of them
	//              was the running kernel. A source with kernel rows and no
	//              running row (no uname, a uname naming nothing installed, a
	//              container reporting its host's kernel) was not judged, even
	//              when linux-libc-dev makes it "covered".
	credVulnerable := map[store.AdvisoryKey]store.AdvisoryVuln{}
	present := map[string]bool{}
	covered := map[string]bool{}
	kernel := map[string]bool{}
	running := map[string]bool{}
	adv := store.Advisories{}
	skippedKernel := 0
	for _, pkg := range cred.Installed {
		present[pkg.Name] = true
		switch domain.ClassifyKernelPackage(cred.KernelRelease, pkg.Name, pkg.Binary, pkg.Version) {
		case domain.KernelUnknown, domain.KernelInstalledNotRunning:
			// Inventory, not a claim: not matched, and not "covered" either — an
			// inferred finding on the kernel is left standing rather than refuted
			// by a read that judged nothing about it. The running ABI's own rows
			// cover the source when they are present.
			kernel[pkg.Name] = true
			skippedKernel++
			continue
		case domain.KernelRunning:
			kernel[pkg.Name] = true
			running[pkg.Name] = true
		}
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
	// judged says the read produced a positive judgement about a source: it
	// carried rows for it and judged them, and if any were kernel rows the
	// running kernel was among them.
	judged := func(pkg string) bool {
		return present[pkg] && covered[pkg] && (!kernel[pkg] || running[pkg])
	}

	// Raise a credentialed finding for each confirmed (package, cve): exact match,
	// source=credentialed, confidence 1.0 (the version was read, not inferred).
	for key, v := range credVulnerable {
		id, reopened, err := (store.Findings{}).Upsert(ctx, conn, store.Finding{
			AssetID:    assetID,
			RuleID:     c.advisoryRuleID,
			DedupKey:   fmt.Sprintf("credentialed|%s|%s|%s", assetID, key.Package, key.CVE),
			Locator:    key.Package,
			Severity:   severityFromCVSS(v.CVSSBase),
			Confidence: 1.0,
			Source:     "credentialed",
			VulnDefID:  v.VulnDefID,
		}, now)
		if err != nil {
			return err
		}
		if reopened {
			// A finding this path closed and a later read raised again: the
			// history says both, or it says the opposite of the truth (a
			// closed finding shown open, with "remediated" as its last word).
			if err := (store.Findings{}).RecordTransition(ctx, conn, id, "remediated", "open",
				fmt.Sprintf("re-detected by a later credentialed read (release %s, kernel %q): %s %s",
					cred.Release, cred.KernelRelease, key.Package, key.CVE), now); err != nil {
				return err
			}
		}
	}

	if skippedKernel > 0 {
		c.log.DebugContext(ctx, "credentialed read: kernel packages held as inventory, not matched",
			"asset_id", assetID, "kernel_release", cred.KernelRelease, "packages", skippedKernel)
	}

	// Supersession: every inferred advisory finding for a covered package is resolved
	// by the credentialed read — matched → superseded, unmatched → refuted. And the
	// read's own earlier claims: a credentialed finding this read no longer matches
	// is remediated — but only where the read JUDGED the package (or no longer
	// carries it at all: a credentialed read is the whole inventory, so absence is
	// removal) AND the release's keyspace knows the package. A release key with no
	// rows for the package (an upgrade whose advisories are not imported yet, or a
	// host that renamed its release) cannot say the claim is gone, only that it
	// has no data — and ADR-068's rule applies: no data is never a clean verdict.
	inferred, err := (store.Findings{}).AdvisoryFindingsForAsset(ctx, conn, assetID)
	if err != nil {
		return err
	}
	keyspaceKnows := map[string]bool{}
	for _, f := range inferred {
		if f.Source == "credentialed" {
			if _, still := credVulnerable[store.AdvisoryKey{Package: f.Package, CVE: f.CVE}]; still {
				continue
			}
			if present[f.Package] && !judged(f.Package) {
				continue // the read carried the package and judged nothing positive about it: the claim stands
			}
			if _, seen := keyspaceKnows[f.Package]; !seen {
				fixes, err := adv.FixesFor(ctx, conn, cred.Release, f.Package)
				if err != nil {
					return err
				}
				keyspaceKnows[f.Package] = len(fixes) > 0
			}
			if !keyspaceKnows[f.Package] {
				continue // this release's keyspace has no data for the package: not a withdrawal
			}
			closed, err := (store.Findings{}).MarkRemediated(ctx, conn, f.ID, now)
			if err != nil {
				return err
			}
			if closed {
				// The facts the loop established, not a cause it did not: which
				// read, at which release and kernel, no longer matched the key.
				if err := (store.Findings{}).RecordTransition(ctx, conn, f.ID, f.Status, "remediated",
					fmt.Sprintf("a later credentialed read (release %s, kernel %q) no longer matches %s %s",
						cred.Release, cred.KernelRelease, f.Package, f.CVE), now); err != nil {
					return err
				}
			}
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
//
// The NEWEST such observation decides. A host group can hold several (a Core
// restart, a re-dispatch, two credentialed jobs inside one sweep interval), and
// the sweep lists them oldest first; since the read also withdraws claims, the
// stalest read must not overrule the current one (security review, measured).
func credentialedInventory(h host) *packagePayload {
	var newest *packagePayload
	var newestAt time.Time
	for _, o := range h.obs {
		if o.Type != store.ObsPackage {
			continue
		}
		var p packagePayload
		if err := json.Unmarshal(o.Payload, &p); err != nil {
			continue
		}
		if p.ReleaseSource != "os-release" || len(p.Installed) == 0 {
			continue
		}
		if !domain.ReleaseTokenValid(p.Release) || !domain.ReleaseTokenValid(p.Family) {
			continue // the same grammar credentialedAttribution applies (ADR-095): one field, one rule
		}
		// The Core-side site of the kernel-release grammar (ADR-095's two-site
		// rule): a token the engine should have refused is treated as unread,
		// so kernel packages are judged neither way rather than by a string a
		// months-old or compromised scan point build chose.
		if p.KernelRelease != "" && !domain.KernelReleaseValid(p.KernelRelease) {
			p.KernelRelease = ""
		}
		if newest == nil || o.ObservedAt.After(newestAt) {
			pp := p
			newest, newestAt = &pp, o.ObservedAt
		}
	}
	return newest
}
