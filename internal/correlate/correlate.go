// Package correlate turns observations into assets.
//
// ============================================================================
// This is where the observation-first model stops being a data shape and starts
// being an inventory (ADR-006).
// ============================================================================
//
// Scan points emit immutable, timestamped, vantage-tagged records of what was
// seen. Nothing in the fleet writes an asset. This package is the one place that
// reads those records and decides which host they belong to, and it is Core-side
// for the reason ADR-006 gives: the reasoning that produced an asset must not
// happen in a distributed fleet running months-old builds, with the evidence
// discarded once the row is written.
//
// # The decision is pure; only the reading and writing are here
//
// `internal/domain.Resolve` holds the merge rule and touches nothing. This
// package gathers candidates, calls it, and applies the verdict. The split is
// what makes a merge replayable over history against a corrected rule — and a
// merge is the one decision in this system that cannot be undone by looking
// again, because it interleaves two hosts' findings and timelines irreversibly.
//
// # A sweeper, not an ingest hook
//
// Correlation runs periodically over accepted-but-unresolved observations rather
// than inline at ingest, and the reason is ADR-026's ratchet: an observation
// lands `pending` and is promoted to `accepted` by the terminal ack, so there is
// no moment during ingest when a submission is both complete and visible. A
// correlation that failed inline would also take the observation with it; one
// that fails here leaves the row unresolved and tries again.
package correlate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/domain"
	"github.com/effaaykhan/cvap/internal/rules"
	"github.com/effaaykhan/cvap/internal/store"
)

// AddressWindow is how long an address is evidence that a host has not changed.
//
// ADR-007 ranks "IP within a time window" as weak, and the window is the whole
// of its meaning: an address seen on this asset an hour ago is reasonable
// evidence, and the same address last seen three months ago is evidence of
// nothing. Outside it an observation becomes a new asset and the stale interval
// is closed.
//
// Seven days is a DHCP lease scale rather than a scan interval: the question is
// "could this address plausibly still be the same host", and a fortnightly scan
// of a network on 24-hour leases should not merge across the gap.
const AddressWindow = 7 * 24 * time.Hour

// Interval is how often the sweep runs.
//
// Periodic because the trigger is the ABSENCE of an event: an observation
// arrives, is promoted by a terminal ack that may come minutes later, and
// nothing then announces that it is ready to correlate.
const Interval = 30 * time.Second

// Batch bounds one pass. A tenant that has just ingested a /16 sweep should not
// hold a transaction open across the whole of it.
const Batch = 500

// Correlator is the sweep.
type Correlator struct {
	db  *store.DB
	log *slog.Logger
	now func() time.Time

	// rules is the loaded, validated rule set, refreshed once per sweep. The
	// finding pipeline runs them over each asset as it is resolved.
	//
	// Held on the correlator rather than reloaded per host because they are
	// global (ADR-009) and do not change within a sweep; a rule pack import
	// between sweeps is picked up at the next one.
	rules []rules.Rule

	// advisoryRuleID is the seeded advisory-version-match rule (ADR-070), loaded
	// once per sweep beside the rules. Advisory findings hang on it to satisfy
	// rule_id-always (ADR-009, non-negotiable #4); the CVE is the vuln_def_id. uuid.Nil disables the
	// advisory path for the sweep — the seed is missing, and inventing a rule_id
	// is worse than raising no advisory finding.
	advisoryRuleID uuid.UUID
}

func New(db *store.DB, log *slog.Logger) *Correlator {
	return &Correlator{db: db, log: log, now: time.Now}
}

// Run sweeps until ctx ends.
//
// Never returns an error, for the reason Sweeper does not: a supervisor that
// restarted the process on a transient database failure would turn a blip into
// an outage of the thing building the inventory.
func (c *Correlator) Run(ctx context.Context) {
	t := time.NewTicker(Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := c.sweep(ctx); err != nil && ctx.Err() == nil {
			c.log.ErrorContext(ctx, "correlation sweep failed", slog.Any("error", err))
		}
	}
}

// SweepOnce runs a single pass.
//
// Exported so an integration test can drive the pipeline deterministically
// rather than waiting on the ticker — a test that slept for the interval would
// be slow and would still be racing it.
func (c *Correlator) SweepOnce(ctx context.Context) error { return c.sweep(ctx) }

func (c *Correlator) sweep(ctx context.Context) error {
	// The single unscoped read this package needs, for the same reason the lease
	// sweeper needs one: a sweep has no tenant to inherit (ADR-036).
	tenants, err := c.db.ActiveTenantIDs(ctx)
	if err != nil {
		return err
	}

	// Load the rules once per sweep. Global tables have no RLS, so any tenant
	// connection reads them; the first tenant's is as good as any. A rule that
	// names an evaluator this build does not implement, or carries a malformed
	// threshold, fails HERE — loudly, once a sweep — rather than silently never
	// firing (internal/rules.Load).
	if len(tenants) > 0 {
		if err := c.loadRules(ctx, tenants[0]); err != nil {
			// A bad rule set is not one tenant's problem, so it stops the sweep
			// rather than being logged per tenant. The previous sweep's rules
			// are not reused: running a rule set nobody validated is the failure
			// Load exists to prevent.
			c.rules = nil
			c.log.ErrorContext(ctx, "rule set failed to load; no findings this sweep",
				slog.Any("error", err))
		}
	}

	for _, t := range tenants {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := c.correlateTenant(ctx, t); err != nil {
			// One tenant's failure does not stop the others: a poisoned
			// observation in one estate must not stall every other customer's
			// inventory.
			c.log.ErrorContext(ctx, "correlation failed for tenant",
				slog.String("tenant_id", t.String()), slog.Any("error", err))
		}
	}
	return nil
}

// host is every observation of one address in one sweep, which is the unit a
// merge decision is made about.
//
// Grouped by ADDRESS rather than by observation, because identity is a property
// of a host and the evidence for it is spread across several observations: the
// certificate comes from one service observation, the host key from another, the
// address from all of them. Deciding per observation would ask the merge rule to
// adjudicate one key at a time, which is precisely the corroboration ADR-007
// requires it to consider together.
type host struct {
	address string
	obs     []store.Observation
	keys    []domain.IdentityKey
	seenAt  time.Time
}

// loadRules reads and validates the active core rules.
func (c *Correlator) loadRules(ctx context.Context, anyTenant store.TenantID) error {
	var rows []store.RuleRow
	var advisoryRuleID uuid.UUID
	if err := c.db.Read(ctx, anyTenant, func(ctx context.Context, conn *store.Conn) error {
		var err error
		if rows, err = (store.Rules{}).ActiveCoreRules(ctx, conn); err != nil {
			return err
		}
		// The advisory-match rule (ADR-070). A missing seed is not fatal to the
		// sweep — the rule findings still run — so a not-found leaves the id Nil
		// and disables only the advisory path. Log it loudly: silently producing
		// zero advisory findings forever is exactly the silent-pass this project
		// treats as worse than a failure (migration 0039 should always be applied).
		id, err := (store.Rules{}).AdvisoryMatchRuleID(ctx, conn)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				advisoryRuleID = uuid.Nil
				c.log.WarnContext(ctx, "advisory-version-match rule not seeded; advisory findings disabled this sweep (migration 0039 missing?)")
				return nil
			}
			return err
		}
		advisoryRuleID = id
		return nil
	}); err != nil {
		return err
	}
	c.advisoryRuleID = advisoryRuleID
	in := make([]rules.Rule, 0, len(rows))
	for _, r := range rows {
		in = append(in, rules.Rule{
			ID: r.ID, Name: r.Name, Category: r.Category, Evaluator: r.Evaluator,
			Params: r.Params, Severity: r.Severity, Confidence: r.Confidence,
			CWE: r.CWE, Remediation: r.Remediation, Version: r.Version,
		})
	}
	loaded, err := rules.Load(in, c.now())
	if err != nil {
		return err
	}
	c.rules = loaded
	return nil
}

func (c *Correlator) correlateTenant(ctx context.Context, tenant store.TenantID) error {
	now := c.now()

	var pending []store.Observation
	err := c.db.Read(ctx, tenant, func(ctx context.Context, conn *store.Conn) error {
		var err error
		pending, err = (store.Observations{}).ListUnresolved(ctx, conn,
			now.Add(-observedWindow), now, Batch)
		return err
	})
	if err != nil {
		return err
	}
	if len(pending) == 0 {
		return nil
	}

	// Age out addresses that have stopped being observed, so `valid_to IS NULL`
	// keeps meaning "is here now" rather than "was here once". Same window that
	// gives `ip_window` its meaning: outside it the address is evidence of
	// nothing, and the resolver already refuses to attach on it.
	if err := c.db.Write(ctx, tenant, func(ctx context.Context, conn *store.Conn) error {
		n, err := (store.AssetAddresses{}).CloseStale(ctx, conn, now.Add(-AddressWindow), now)
		if err == nil && n > 0 {
			c.log.InfoContext(ctx, "closed stale address intervals",
				slog.String("tenant_id", tenant.String()), slog.Int64("closed", n))
		}
		return err
	}); err != nil {
		return err
	}

	// Zone types for this tenant, for the exposure rules. Loaded once per sweep
	// per tenant and read from a closure by the evaluator, which must do no I/O
	// of its own — that is what keeps it re-runnable over history.
	zoneType, err := c.zoneTypes(ctx, tenant)
	if err != nil {
		return err
	}

	for _, h := range groupByAddress(pending) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := c.resolveHost(ctx, tenant, h, zoneType, now); err != nil {
			c.log.ErrorContext(ctx, "could not resolve a host",
				slog.String("tenant_id", tenant.String()),
				slog.String("address", h.address), slog.Any("error", err))
		}
	}
	return nil
}

// resolveHost decides and applies, in ONE transaction.
//
// One transaction because the pieces are not independently correct: closing an
// address interval, opening the new one, recording the identity keys and marking
// the observations resolved describe a single decision, and a crash between any
// two of them leaves the state the unique index in migration 0031 exists to
// prevent — or an observation marked resolved against an asset that was never
// written.
func (c *Correlator) resolveHost(ctx context.Context, tenant store.TenantID, h host, zoneType func(uuid.UUID) string, now time.Time) error {
	return c.db.Write(ctx, tenant, func(ctx context.Context, conn *store.Conn) error {
		candidates, err := c.candidatesFor(ctx, conn, h)
		if err != nil {
			return err
		}

		v := domain.Resolve(h.keys, candidates, now, AddressWindow)

		assetID := v.AssetID
		switch v.Decision {
		case domain.DecisionQueue:
			// Never a guess. Conflicting or ambiguous evidence is an operator's
			// decision, and the evidence is copied into the queue so the item
			// outlives the observation partition that raised it.
			for _, k := range h.keys {
				if k.Type.Strength() == 0 {
					continue
				}
				if err := (store.ResolutionQueue{}).Enqueue(ctx, conn, v, k, now); err != nil {
					return err
				}
			}
			c.log.WarnContext(ctx, "asset resolution needs an operator",
				slog.String("tenant_id", tenant.String()),
				slog.String("address", h.address),
				slog.String("reason", v.Reason))
			// The observations stay UNRESOLVED. An item nobody has adjudicated
			// must not look correlated, and `asset_id IS NULL` is what the
			// finding pipeline reads as "not yet".
			return nil

		case domain.DecisionNewAsset:
			a, err := (store.Assets{}).Create(ctx, conn, store.Asset{})
			if err != nil {
				return err
			}
			assetID = a.ID
		}

		// Attach and Merge both reach here, and the difference is what gets
		// written: a merge records the identity keys that justified it, an
		// attach records none. Weak evidence moves an observation onto an asset
		// and never claims two hosts are one (ADR-007).
		if v.Decision == domain.DecisionMerge || v.Decision == domain.DecisionNewAsset {
			for _, k := range v.Agreeing {
				if err := (store.AssetIdentityKeys{}).Record(ctx, conn, assetID, k, now); err != nil {
					return err
				}
			}
			if v.Decision == domain.DecisionNewAsset {
				// A new asset records everything it was seen with, so the NEXT
				// scan has something to merge against. Without this the resolver
				// would create a fresh asset on every pass and never accumulate
				// the keys that stop it.
				for _, k := range h.keys {
					if k.Type.Strength() < 2 {
						continue // weak keys are the address, held below
					}
					if err := (store.AssetIdentityKeys{}).Record(ctx, conn, assetID, k, now); err != nil {
						return err
					}
				}
			}
		}

		if h.address != "" {
			if err := (store.AssetAddresses{}).Open(ctx, conn, assetID, h.address, h.seenAt); err != nil {
				return err
			}
			if err := (store.AssetAddresses{}).TouchLive(ctx, conn, assetID, h.address, h.seenAt); err != nil {
				return err
			}
		}
		if err := (store.Assets{}).TouchLastSeen(ctx, conn, assetID, h.seenAt); err != nil {
			return err
		}

		if err := c.deriveServices(ctx, conn, assetID, h); err != nil {
			return err
		}

		// OS attribution from the services just derived (B21, ADR-061): read the
		// per-service hints, apply the precedence, write family + provenance to
		// the asset. In the same transaction as the services it is derived from.
		family, err := c.deriveAttribution(ctx, conn, assetID, h)
		if err != nil {
			return err
		}

		// Release resolution (P3.3, ADR-064). A credentialed `package` observation
		// carries the exact family AND release read from /etc/os-release — ground
		// truth — and OUTRANKS the service-inferred attribution above. It resolves
		// both, at confidence 1.0, WITHOUT the `family != ""` gate that the band-vote
		// path needs (ADR-089): gating the exact signal behind the weaker inferred
		// one inverts the confidence ordering, and a package-only sweep has no
		// inferred family at all, so the gate made ADR-077 unreachable on the very
		// data shape it was built for. Otherwise the band vote runs, and only under a
		// known family — release is far less ambiguous once the family is fixed, and a
		// family-only host is the honest state to leave when nothing resolves.
		var release string
		var releaseConf float32
		if facts, ok := credentialedAttribution(h); ok {
			// applyCredentialedAttribution writes the family itself (ADR-090);
			// nothing below reads the local, so it is not reassigned here.
			if release, releaseConf, err = c.applyCredentialedAttribution(ctx, conn, assetID, facts); err != nil {
				return err
			}
		} else if family != "" {
			if release, releaseConf, err = c.deriveRelease(ctx, conn, assetID, h); err != nil {
				return err
			}
		}

		// Findings, in the SAME transaction: the moment the derived model
		// changed is the moment to re-judge it, and a finding written against an
		// asset whose resolution rolled back would reference a row that never
		// committed. Environment drives the self-signed rule's dev exemption.
		env, err := (store.Assets{}).EnvironmentOf(ctx, conn, assetID)
		if err != nil {
			return err
		}
		if err := c.evaluateFindings(ctx, conn, assetID, env, h, zoneType, now); err != nil {
			return err
		}

		// Advisory findings (ADR-070): the last link of P3.3 — a resolved release
		// plus a service's banner version, matched against the advisory keyspace,
		// becomes a finding carrying its CVE. Same transaction, after the release is
		// written. Skipped when the release did not resolve or the seed is absent.
		if release != "" && c.advisoryRuleID != uuid.Nil {
			if err := c.evaluateAdvisories(ctx, conn, assetID, release, float64(releaseConf), h, now); err != nil {
				return err
			}
		}

		// Credentialed findings (ADR-077/087/088): a credentialed-host engine's
		// `package` observation carries exact versions, so it matches without revision
		// blindness AND resolves the inferred findings it now speaks to — superseding a
		// match, refuting a non-match. Same transaction. A no-op unless this host has a
		// credentialed inventory observation.
		if err := c.evaluateCredentialed(ctx, conn, assetID, h, now); err != nil {
			return err
		}

		for _, o := range h.obs {
			if err := (store.Observations{}).Resolve(ctx, conn, o.ID, o.ObservedAt, assetID); err != nil {
				return err
			}
		}
		return nil
	})
}

// zoneTypes builds a zone-id -> zone-type resolver for a tenant.
//
// Read once per tenant per sweep and captured in a closure, so the evaluator
// does no I/O — which is what lets a rule be re-run over history and reach the
// same answer. A zone id the map does not know resolves to "", which the
// exposure rule treats as not-untrusted: an unknown zone is not evidence of
// exposure.
func (c *Correlator) zoneTypes(ctx context.Context, tenant store.TenantID) (func(uuid.UUID) string, error) {
	m := map[uuid.UUID]string{}
	if err := c.db.Read(ctx, tenant, func(ctx context.Context, conn *store.Conn) error {
		zs, err := (store.Zones{}).List(ctx, conn)
		if err != nil {
			return err
		}
		for _, z := range zs {
			m[z.ID] = string(z.Type)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return func(id uuid.UUID) string { return m[id] }, nil
}

// candidatesFor gathers the assets this evidence could belong to.
//
// Two sources: an asset already holding one of the observed identity keys, and
// the asset currently holding the observed address. Both are indexed lookups —
// the partial unique index on live key values, and the one migration 0031 added.
func (c *Correlator) candidatesFor(ctx context.Context, conn *store.Conn, h host) ([]domain.Candidate, error) {
	byID := map[uuid.UUID]*domain.Candidate{}

	add := func(id uuid.UUID) error {
		if id == uuid.Nil {
			return nil
		}
		if _, ok := byID[id]; ok {
			return nil
		}
		keys, err := (store.AssetIdentityKeys{}).ForAsset(ctx, conn, id)
		if err != nil {
			return err
		}
		byID[id] = &domain.Candidate{AssetID: id, Keys: keys}
		return nil
	}

	for _, k := range h.keys {
		if k.Type.Strength() < 2 {
			continue // a weak key is not a lookup, it is the address below
		}
		id, err := (store.AssetIdentityKeys{}).LiveByValue(ctx, conn, k.Type, k.Value)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		if err == nil {
			if err := add(id); err != nil {
				return nil, err
			}
		}
	}

	if h.address != "" {
		id, lastSeen, err := (store.AssetAddresses{}).LiveHolder(ctx, conn, h.address)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		if err == nil {
			if err := add(id); err != nil {
				return nil, err
			}
			// HeldAddress and AddressLastSeen are only meaningful for the asset
			// that actually holds this address, which is why they are set here
			// and not in `add`. The resolver compares the address rather than
			// trusting the timestamp to refer to the right one.
			byID[id].HeldAddress = h.address
			byID[id].AddressLastSeen = lastSeen
		}
	}

	out := make([]domain.Candidate, 0, len(byID))
	for _, c := range byID {
		out = append(out, *c)
	}
	return out, nil
}

// deriveServices writes the service rows for this host.
func (c *Correlator) deriveServices(ctx context.Context, conn *store.Conn, assetID uuid.UUID, h host) error {
	for _, o := range h.obs {
		if o.Type != "service" {
			continue
		}
		var p servicePayload
		if err := json.Unmarshal(o.Payload, &p); err != nil {
			continue // a payload Core cannot read is not a service
		}
		if p.Port == 0 {
			continue // a refusal observation carries no port
		}

		s := store.Service{
			AssetID: assetID, Port: int(p.Port), Protocol: orDefault(p.Protocol, "tcp"),
			Name: p.Service, Product: p.Product, Version: p.Version,
			IdentificationMethod: p.Method, Softmatch: p.Softmatch,
			Solicited: p.Solicited, SafetyMode: p.SafetyMode,
			IdentificationProbe: p.Probe,
			TLS:                 p.TLS, SSH: p.SSH,
		}
		if o.Confidence != nil {
			s.IdentificationConfidence = o.Confidence
			if p.Version != "" {
				// The same number, and deliberately: a version lifted from a
				// banner is exactly as believable as the identification that
				// read it. They diverge when a credentialed source supplies a
				// version for a service identified from the network, which is
				// out of MVP scope.
				s.VersionConfidence = o.Confidence
			}
		}
		if err := (store.Services{}).Upsert(ctx, conn, s, o.ObservedAt); err != nil {
			return err
		}
	}
	return nil
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}

// deriveAttribution turns the per-service OS hints into one asset-level
// attribution and writes it (B21, ADR-061). The DECISION — precedence between
// services, the three-state outcome, provenance — is domain.AttributeOS; this
// gathers the evidence and applies the verdict, the same pure/impure split as
// resolveHost itself. A family-only result (release nil) is written and is
// distinct from no attribution, which leaves the columns null.
func (c *Correlator) deriveAttribution(ctx context.Context, conn *store.Conn, assetID uuid.UUID, h host) (string, error) {
	var ev []domain.OSEvidence
	for _, o := range h.obs {
		if o.Type != "service" {
			continue
		}
		var p servicePayload
		if err := json.Unmarshal(o.Payload, &p); err != nil {
			continue
		}
		if p.OS == nil || strings.TrimSpace(p.OS.Hint) == "" {
			continue
		}
		var conf float32
		if o.Confidence != nil {
			conf = float32(*o.Confidence)
		}
		ev = append(ev, domain.OSEvidence{
			Service:    normaliseOSService(p.Service),
			Port:       p.Port,
			Family:     strings.ToLower(strings.TrimSpace(p.OS.Hint)),
			Confidence: conf,
		})
	}
	a := domain.AttributeOS(ev)
	if a.DistroFamily == "" {
		return "", nil // no attribution: leave the asset's OS columns null
	}
	prov, err := json.Marshal(a.Provenance)
	if err != nil {
		return "", err
	}
	if err := (store.Assets{}).SetAttribution(ctx, conn, assetID, a.DistroFamily, a.DistroRelease, a.Confidence, prov); err != nil {
		return "", err
	}
	return a.DistroFamily, nil
}

// deriveRelease resolves the distro RELEASE from the observed service versions
// (P3.3, ADR-064), the second half of attribution. The DECISION — band voting,
// the threshold, provenance roles — is domain.ResolveRelease; this gathers the
// votes and applies the verdict, the same pure/impure split as deriveAttribution.
//
// For each identified service it reads the advisory keyspace rows for that
// product (through the product->package map), bands both the observed version and
// the keyspace fixed versions with the ONE band authority (domain.UpstreamBand),
// and casts a vote: the releases whose band equals the observed band. Absence is
// not a vote against, in both places — a product with no keyspace analogue and an
// observed version that matches no band both ABSTAIN (ADR-064). The provenance is
// written even when unresolved, so the abstentions are visible.
// Returns the resolved release ("" if unresolved) and its confidence (ADR-065),
// so the caller can match advisories against it in the same transaction (ADR-070)
// without a re-read, and compose the finding's confidence from it (ADR-072).
func (c *Correlator) deriveRelease(ctx context.Context, conn *store.Conn, assetID uuid.UUID, h host) (string, float32, error) {
	// The credentialed precedence (ADR-076/077) is NOT here — it is applied upstream
	// in resolveHost, ungated by family (ADR-089), so a package-only sweep reaches it.
	// This function is the band-vote INFERENCE only, reached when no credentialed
	// `package` observation is present. Keeping the exact-release branch out of here
	// is deliberate: it lived behind this function's own `family != ""` caller-gate,
	// which is exactly what made ADR-077 unreachable on real data.
	var votes []domain.ReleaseVote
	// One vote per listening endpoint (port/protocol), the same unit the services
	// table dedups on: a service seen across several observations (a rescan) must
	// cast ONE vote, or a duplicated observation would inflate the tally and cross
	// the threshold on its own. First observation per endpoint wins.
	seen := map[string]bool{}
	for _, o := range h.obs {
		if o.Type != "service" {
			continue
		}
		var p servicePayload
		if err := json.Unmarshal(o.Payload, &p); err != nil {
			continue
		}
		if p.Product == "" {
			continue // service not identified to a product: not a release candidate at all
		}
		endpoint := fmt.Sprintf("%d/%s", p.Port, orDefault(p.Protocol, "tcp"))
		if seen[endpoint] {
			continue
		}
		seen[endpoint] = true
		// A product WITH no version still becomes a vote — with an empty band it
		// abstains ("no version identified"), so a service that was seen but could
		// not contribute is VISIBLE in the provenance rather than silently dropped
		// (ADR-064: absence must be visible).
		rows, err := (store.Advisories{}).ReleasesForProduct(ctx, conn, p.Product)
		if err != nil {
			return "", 0, err
		}
		band := domain.UpstreamBand(p.Version)
		candSet := map[string]struct{}{}
		if band != "" {
			for _, r := range rows {
				if domain.UpstreamBand(r.FixedVersion) == band {
					candSet[r.Release] = struct{}{}
				}
			}
		}
		candidates := make([]string, 0, len(candSet))
		for r := range candSet {
			candidates = append(candidates, r)
		}
		sort.Strings(candidates)
		votes = append(votes, domain.ReleaseVote{
			Service:     normaliseOSService(p.Service),
			Port:        p.Port,
			Product:     p.Product,
			Band:        band,
			Candidates:  candidates,
			HasAnalogue: len(rows) > 0,
		})
	}
	if len(votes) == 0 {
		return "", 0, nil // no service carried a product+version: nothing to resolve or record
	}

	res := domain.ResolveRelease(votes)
	prov, err := json.Marshal(res.Provenance)
	if err != nil {
		return "", 0, err
	}
	if err := (store.Assets{}).SetRelease(ctx, conn, assetID, res.Release, res.Confidence, prov); err != nil {
		return "", 0, err
	}
	// res.Release is nil when band voting did not resolve (ADR-064); "" then, which
	// the caller reads as "no release to match advisories against".
	if res.Release == nil {
		return "", 0, nil
	}
	return *res.Release, res.Confidence, nil
}

// credentialedFacts is the ground-truth attribution read from /etc/os-release on a
// credentialed host: both the family (ID) and the release. Ground truth — it
// outranks the service-inferred family and the band-vote release alike.
type credentialedFacts struct {
	Family  string // os-release ID, e.g. "ubuntu"
	Release string // release key (codename, or ID-major for rpm)
}

// credentialedAttribution returns the exact family+release read from a credentialed
// `package` observation (/etc/os-release), if the host has a usable one. This is the
// read side of the ADR-076/077/089 precedence decision: an exact read on the host
// outranks the service-inferred attribution and the band-vote release. It requires a
// non-empty Family so it can resolve attribution self-sufficiently — a package
// payload without a family (pre-ADR-089, or the dormant/instrument shapes) is not a
// self-sufficient attribution and falls through to band voting, unchanged.
func credentialedAttribution(h host) (credentialedFacts, bool) {
	for _, o := range h.obs {
		if o.Type != store.ObsPackage {
			continue
		}
		var p packagePayload
		if err := json.Unmarshal(o.Payload, &p); err != nil {
			continue // a malformed package payload is not attribution we can trust
		}
		if p.ReleaseSource == "os-release" && p.Release != "" && p.Family != "" {
			return credentialedFacts{Family: p.Family, Release: p.Release}, true
		}
	}
	return credentialedFacts{}, false
}

// applyCredentialedAttribution writes the exact family and release to the asset at
// confidence 1.0, with provenance recording that each outranked the inferred signal
// (ADR-089). Family first, because SetRelease is guarded by distro_family NOT NULL.
// One code path for release resolution: this does NOT go through deriveRelease's
// band vote — the exact read is the whole answer.
func (c *Correlator) applyCredentialedAttribution(ctx context.Context, conn *store.Conn, assetID uuid.UUID, f credentialedFacts) (string, float32, error) {
	rel := f.Release
	famProv, err := json.Marshal(map[string]any{
		"source": "os-release",
		"family": f.Family,
		"basis":  "exact /etc/os-release ID read on the host; outranks service-inferred attribution (ADR-089)",
	})
	if err != nil {
		return "", 0, err
	}
	if err := (store.Assets{}).SetAttribution(ctx, conn, assetID, f.Family, &rel, 1.0, famProv); err != nil {
		return "", 0, err
	}
	relProv, err := json.Marshal(map[string]any{
		"source":  "package_manager",
		"release": f.Release,
		"basis":   "exact release read from /etc/os-release; outranks band voting (ADR-076/077/089)",
	})
	if err != nil {
		return "", 0, err
	}
	if err := (store.Assets{}).SetRelease(ctx, conn, assetID, &rel, 1.0, relProv); err != nil {
		return "", 0, err
	}
	return f.Release, 1.0, nil
}

// normaliseOSService collapses service names that name the same platform source
// for attribution — SMB answers as microsoft-ds or netbios-ssn — onto the token
// the precedence table in domain ranks.
func normaliseOSService(service string) string {
	switch service {
	case "microsoft-ds", "netbios-ssn":
		return "smb"
	default:
		return service
	}
}
