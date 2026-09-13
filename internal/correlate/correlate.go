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
	"strconv"
	"strings"
	"sync"
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

	// agedAt is when each tenant's ageing pass last ran (AgeingInterval).
	mu       sync.Mutex
	agedAt   map[store.TenantID]time.Time
	ageEvery *time.Duration

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

// AgeingInterval bounds how often one tenant's addresses are aged and its
// stale queue items expired (ADR-096): once an hour is plenty for a seven-day
// window, and the alternative was measured at ten seconds per sweep.
const AgeingInterval = time.Hour

// AgeEvery overrides AgeingInterval — zero ages on every sweep. For tests
// that shift the clock in the database and need the next sweep to notice.
func (c *Correlator) AgeEvery(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ageEvery = &d
}

func (c *Correlator) shouldAge(tenant store.TenantID, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.agedAt == nil {
		c.agedAt = map[store.TenantID]time.Time{}
	}
	every := AgeingInterval
	if c.ageEvery != nil {
		every = *c.ageEvery
	}
	if last, ok := c.agedAt[tenant]; ok && now.Sub(last) < every {
		return false
	}
	c.agedAt[tenant] = now
	return true
}

func (c *Correlator) unstampAge(tenant store.TenantID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.agedAt, tenant)
}

// ageTenant is the ageing pass: stale queue items expire, stale address
// intervals close.
func (c *Correlator) ageTenant(ctx context.Context, tenant store.TenantID, now time.Time) error {
	return c.db.Write(ctx, tenant, func(ctx context.Context, conn *store.Conn) error {
		expired, err := (store.ResolutionQueue{}).ExpireUnplaceable(ctx, conn, now.Add(-AddressWindow), now)
		if err != nil {
			return err
		}
		if len(expired) > 0 {
			// A close-out nothing announces is a refusal that vanished: an
			// operator watching the Health chip fall to zero finds the reason
			// here (ADR-096). The list is capped; the count is not.
			const maxListed = 50
			listed := expired
			if len(listed) > maxListed {
				listed = listed[:maxListed]
			}
			if err := (store.AuditEvents{}).Record(ctx, conn, store.AuditEvent{
				ActorType:    store.ActorSystem,
				Action:       "identity.items_expired",
				ResourceType: "resolution_queue",
				Detail: map[string]any{
					"addresses":     listed,
					"address_count": len(expired),
					"note":          "pending items older than the window that no transition could reach — they named no candidate, or none of their candidates still held the address — were closed as expired (ADR-096)",
				},
			}); err != nil {
				return err
			}
		}
		n, err := (store.AssetAddresses{}).CloseStale(ctx, conn, now.Add(-AddressWindow), now)
		if err == nil && n > 0 {
			c.log.InfoContext(ctx, "closed stale address intervals",
				slog.String("tenant_id", tenant.String()), slog.Int64("closed", n))
		}
		return err
	})
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

	// Age out addresses that have stopped being observed, so `valid_to IS NULL`
	// keeps meaning "is here now" rather than "was here once". Same window that
	// gives `ip_window` its meaning: outside it the address is evidence of
	// nothing, and the resolver already refuses to attach on it. BEFORE the
	// nothing-to-do return: ageing is about silence, and a tenant whose every
	// observation is parked has nothing unresolved and everything to age (the
	// review measured a frozen host never ageing because nothing was pending).
	// At most once per AgeingInterval per tenant: a seven-day window does not
	// need thirty-second ageing, and the write measured 0.7 ms per tenant per
	// sweep — ten seconds of a thirty-second sweep at the dev database's
	// tenant count.
	if c.shouldAge(tenant, now) {
		if err := c.ageTenant(ctx, tenant, now); err != nil {
			c.unstampAge(tenant) // a transient fault must not skip the tenant for an hour
			return err
		}
	}
	if len(pending) == 0 {
		return nil
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
		// A handover verdict names the contradicting keys; measure the four
		// continuity facts for the address holder and ask once more
		// (ADR-096). Only a contested host pays for the reads. The decision
		// stays in domain: this gathers facts and hands them over.
		if v.Decision == domain.DecisionQueue && len(v.Handover) > 0 && len(v.Candidates) == 1 {
			for i := range candidates {
				if candidates[i].AssetID != v.Candidates[0] || candidates[i].HeldAddress != h.address {
					continue
				}
				f, err := c.continuityFor(ctx, conn, candidates[i], h, v.Handover, now)
				if err != nil {
					return err
				}
				candidates[i].Continuity = &f
				v = domain.Resolve(h.keys, candidates, now, AddressWindow)
				break
			}
		}

		assetID := v.AssetID
		switch v.Decision {
		case domain.DecisionQueue:
			// Never a guess. Conflicting or ambiguous evidence is an operator's
			// decision, and the evidence is copied into the queue so the item
			// outlives the observation partition that raised it.
			//
			// The WHOLE host group is parked, not only the observation that
			// carried the contested key (ADR-094): a newcomer on a reused
			// lease also answers on ports that carry no key, and an
			// observation left unparked re-groups alone next sweep, finds only
			// the address, and attaches — writing the newcomer's services and
			// findings onto the previous occupant's asset through the back
			// door. Every observation gets an item naming it, so ListUnresolved
			// parks all of them until the adjudication.
			carried := map[uuid.UUID]bool{}
			newItems := 0
			for _, k := range h.keys {
				if k.Type.Strength() == 0 || k.ObservationID == uuid.Nil {
					continue
				}
				inserted, err := (store.ResolutionQueue{}).Enqueue(ctx, conn, v, k, h.address, now)
				if errors.Is(err, store.ErrKeyWithoutService) {
					// Not carried: the address-only fallback below parks the
					// observation, or it would re-group alone next sweep.
					c.log.WarnContext(ctx, "key parked without a service; skipped",
						slog.String("address", h.address), slog.String("key_type", string(k.Type)))
					continue
				}
				if err != nil {
					return err
				}
				carried[k.ObservationID] = true
				if inserted {
					newItems++
				}
			}
			for _, o := range h.obs {
				if carried[o.ID] {
					continue
				}
				inserted, err := (store.ResolutionQueue{}).Enqueue(ctx, conn, v, domain.IdentityKey{
					Type: domain.KeyIPWindow, Value: h.address, Source: "net",
					ObservationID: o.ID, Payload: o.Payload,
				}, h.address, now)
				if err != nil {
					return err
				}
				if inserted {
					newItems++
				}
			}
			c.log.WarnContext(ctx, "asset resolution needs an operator",
				slog.String("tenant_id", tenant.String()),
				slog.String("address", h.address),
				slog.String("reason", v.Reason))
			// A park that nothing announces is a disappearance (B41, ADR-096):
			// the observations wait for an adjudication, the host's inventory
			// stops moving, and until now the only trace was the WARN above.
			// One audit event per sweep that parks something NEW — a
			// re-sweep of an already-parked group is a no-op and raises
			// nothing; a later scan of the contested host parks new items
			// and raises again, bounded by the scan cadence (measured: one
			// per contested address per scan). It carries the address, the
			// reason, the candidates and how many observations this sweep
			// parked. Health counts the pending items and addresses.
			if newItems > 0 {
				cands := make([]string, 0, len(v.Candidates))
				for _, id := range v.Candidates {
					cands = append(cands, id.String())
				}
				// On the contested asset's own timeline: that is where
				// someone asking "why did this host stop updating" looks. An
				// item with no candidate (two hosts on one port at an
				// address nothing holds) is keyed to the address instead.
				resourceType, resourceID := "address", (*uuid.UUID)(nil)
				if len(v.Candidates) > 0 {
					first := v.Candidates[0]
					resourceType, resourceID = "asset", &first
				}
				if err := (store.AuditEvents{}).Record(ctx, conn, store.AuditEvent{
					ActorType:    store.ActorSystem,
					Action:       "identity.contested",
					ResourceType: resourceType,
					ResourceID:   resourceID,
					Detail: map[string]any{
						"address":       h.address,
						"reason":        v.Reason,
						"candidates":    cands,
						"observations":  len(h.obs),
						"parked_items":  newItems,
						"note":          "queued for an operator; the host's observations are parked until adjudicated (B39) or a later scan classifies a rotation (ADR-096)",
						"observed_last": h.seenAt.UTC().Format(time.RFC3339),
					},
				}); err != nil {
					return err
				}
			}
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
			// The address holder lapsed (ADR-096): its contest at this
			// address closes with it. Open below takes the address off it.
			if v.Lapsed != uuid.Nil {
				expired, err := (store.ResolutionQueue{}).CloseExpired(ctx, conn, h.address, v.Lapsed, h.seenAt)
				if err != nil {
					return err
				}
				lapsed := v.Lapsed
				if err := (store.AuditEvents{}).Record(ctx, conn, store.AuditEvent{
					ActorType:    store.ActorSystem,
					Action:       "identity.contest_expired",
					ResourceType: "asset",
					ResourceID:   &lapsed,
					Detail: map[string]any{
						"address":       h.address,
						"items_expired": expired,
						"new_asset":     assetID.String(),
						"note":          "the held key has not answered at the address for a full window while a contradicting key answered on two scans; the occupant lapsed and the newcomer is a new asset, trusted on ADR-094's terms (ADR-096)",
					},
				}); err != nil {
					return err
				}
			}
		}

		// Attach, Merge and NewAsset all reach here, and the difference is what
		// gets written. A merge records the identity keys that JUSTIFIED it. A
		// new asset records everything it was seen with, so the next scan has
		// something to merge against. An attach — weak evidence, the address
		// alone — never claims two hosts are one (ADR-007), but it DOES record
		// the moderate keys the observation carried, for the same reason the new
		// asset does: a host first inventoried before its host key was ever
		// captured would otherwise never gain one, however many later scans saw
		// it. Every one of the three Phase 4 hosts was in that state (S42,
		// ADR-093): an intrusive fingerprint pass captured their ed25519 keys,
		// the observations attached by address, and asset_identity_keys stayed
		// empty — so the credentialed engine had nothing observed to verify
		// against. Which verdict recorded a key is kept with it as provenance
		// (ADR-094), for the audit trail only: whatever recorded it, a key is
		// trust material for ADR-091's observed path at an address only once
		// two distinct SCANS have seen it there — first sight is not an
		// enrolment, whether it came from an attach or a new asset. An SSH
		// host key that contradicts what the asset holds FROM THE SAME SERVICE
		// never reaches here: that is an address handover, and domain.Resolve
		// queues it (ADR-094) rather than attaching — the rule lives in
		// domain, where the next caller cannot forget it. A contradicting
		// certificate DOES reach here (a renewal is the same host) and is
		// carried in v.Contradicted, which the attach branch skips. A key from a different service
		// (a second sshd on 2222 beside the one on 22) contradicts nothing,
		// is recorded as inventory, and is trust material for no port but its
		// own. The sighting's occasion is the SCAN the observation came from,
		// and it is counted at the ADDRESS it came from (ADR-094).
		scanFor := func(k domain.IdentityKey) (uuid.UUID, error) {
			for _, o := range h.obs {
				if o.ID == k.ObservationID {
					return (store.Jobs{}).ScanIDForTask(ctx, conn, o.TaskID)
				}
			}
			return uuid.Nil, nil
		}
		// A key the verdict marked CONTRADICTED (a renewed certificate against
		// the one held, ADR-094) is recorded by the corroborated block below,
		// after the held one is retired, so the two never sit side by side as
		// merge evidence — and never by the plain loop.
		contradicted := func(k domain.IdentityKey) bool {
			for _, x := range append(append([]domain.IdentityKey{}, v.Contradicted...), v.Rotated...) {
				if x.Type == k.Type && x.Value == k.Value && x.Source == k.Source {
					return true
				}
			}
			return false
		}
		// A key rotation (ADR-096): the held SSH key on that port is retired
		// and the observed one recorded with its own provenance — which the
		// trust root EXCLUDES: a takeover of the SSH port alone is
		// indistinguishable from a rotation on banner data, so the inventory
		// moves and the credentialed trust does not, until an operator pins
		// or confirms. A renewed certificate beside it is v.Contradicted and
		// takes the establishment gate below like any renewal — corroborated
		// only once the rotated key itself is established here. The items parked at this address for
		// this asset close as `rotated`, which releases the parked
		// observations back into the sweep; they attach next pass, because
		// the key they carry is now the one the asset holds. Nothing parked
		// is lost. Announced on the asset's timeline like the park was.
		if len(v.Rotated) > 0 {
			var retired, recorded []string
			for _, k := range v.Rotated {
				// Each step is checked, and a step that did nothing is a
				// FAULT that rolls the whole attach back (the host stays
				// parked, the sweep retries): the review measured a key the
				// retire predicate did not match, and a key already live on
				// another asset whose Record was a silent no-op — the asset
				// left keyless while the event said "recorded".
				port, proto := store.SourcePortProto(k.Source)
				n, err := (store.AssetIdentityKeys{}).Retire(ctx, conn, assetID, k.Type, port, proto, h.seenAt)
				if err != nil {
					return err
				}
				if n == 0 {
					return fmt.Errorf("rotation at %s: no live %s from %s on asset %s to retire", h.address, k.Type, k.Source, assetID)
				}
				scanID, err := scanFor(k)
				if err != nil {
					return err
				}
				if _, err := (store.AssetIdentityKeys{}).Record(ctx, conn, assetID, k, h.seenAt, store.KeyFromRotation, scanID, h.address, portOf(k.Source)); err != nil {
					return err
				}
				holder, err := (store.AssetIdentityKeys{}).LiveByValue(ctx, conn, k.Type, k.Value)
				if err != nil {
					return err
				}
				if holder != assetID {
					return fmt.Errorf("rotation at %s: %s from %s is live on asset %s, not recorded on %s", h.address, k.Type, k.Source, holder, assetID)
				}
				retired = append(retired, string(k.Type)+"@"+k.Source)
				recorded = append(recorded, string(k.Type)+"@"+k.Source+" "+k.Value)
			}
			examined := append(append([]domain.IdentityKey{}, v.Rotated...), v.Contradicted...)
			closed, err := (store.ResolutionQueue{}).CloseRotated(ctx, conn, h.address, assetID, examined, h.seenAt)
			if err != nil {
				return err
			}
			if err := (store.AuditEvents{}).Record(ctx, conn, store.AuditEvent{
				ActorType:    store.ActorSystem,
				Action:       "identity.rotated",
				ResourceType: "asset",
				ResourceID:   &assetID,
				Detail: map[string]any{
					"address":      h.address,
					"reason":       v.Reason,
					"retired":      retired,
					"recorded":     recorded,
					"items_closed": closed,
					"note":         "continuity narrows the window and verifies nothing (ADR-096); the recorded key is NOT credentialed trust material until an operator pins or confirms it",
				},
			}); err != nil {
				return err
			}
		}
		if v.Decision == domain.DecisionMerge || v.Decision == domain.DecisionNewAsset {
			from := store.KeyFromMerge
			if v.Decision == domain.DecisionNewAsset {
				from = store.KeyFromNewAsset
			}
			for _, k := range v.Agreeing {
				scanID, err := scanFor(k)
				if err != nil {
					return err
				}
				if _, err := (store.AssetIdentityKeys{}).Record(ctx, conn, assetID, k, h.seenAt, from, scanID, h.address, portOf(k.Source)); err != nil {
					return err
				}
			}
		}
		// An attach that carries a contradiction records NOTHING unless
		// something else agreed (ADR-094): a different host wearing a TLS
		// host's address, with a new certificate and its own sshd, would
		// otherwise ride the forgiven certificate in — its host key recorded
		// on the occupant's asset, two scans later the occupant's trust root
		// (the review measured exactly that). With corroboration — the
		// asset's own steady host key agreed — the contradiction is a
		// renewal: the held certificate is retired and the new one recorded,
		// so the renewal survives the host's next address change.
		//
		// "Agreed" is not enough: the corroborating key must be ESTABLISHED at
		// this address — two distinct scans, like the trust root — because an
		// attach can write what the asset holds, and a key planted one scan
		// earlier would corroborate its planter's certificate the next. The
		// read happens before this sweep records anything, so this scan's own
		// sighting cannot count. An observed SSH host key is a public value
		// (the fingerprint probe verifies no signature), so even established
		// corroboration is an echo, not a proof: it raises the cost to
		// knowing the host key AND holding the address across scans.
		established := false
		if len(v.Contradicted) > 0 {
			for _, k := range v.Corroborated {
				ok, err := (store.AssetIdentityKeys{}).EstablishedAt(ctx, conn, assetID, k, h.address, portOf(k.Source), store.SightingWindow)
				if err != nil {
					return err
				}
				if ok {
					established = true
					break
				}
			}
		}
		uncorroborated := len(v.Contradicted) > 0 && !established
		if uncorroborated {
			c.log.WarnContext(ctx, "contradiction with no established corroboration; no key recorded",
				slog.String("asset_id", assetID.String()),
				slog.String("address", h.address),
				slog.Any("decision", v.Decision),
				slog.Int("contradicted", len(v.Contradicted)))
		}
		// Corroborated on either verdict — an attach the asset's own key
		// agreed with, or a merge — the renewal is applied: the held key of
		// that type on that port is retired and the renewed one recorded.
		if len(v.Contradicted) > 0 && established {
			from := store.KeyFromAttach
			if v.Decision == domain.DecisionMerge {
				from = store.KeyFromMerge
			}
			for _, k := range v.Contradicted {
				port, proto := store.SourcePortProto(k.Source)
				if _, err := (store.AssetIdentityKeys{}).Retire(ctx, conn, assetID, k.Type, port, proto, h.seenAt); err != nil {
					return err
				}
				scanID, err := scanFor(k)
				if err != nil {
					return err
				}
				if _, err := (store.AssetIdentityKeys{}).Record(ctx, conn, assetID, k, h.seenAt, from, scanID, h.address, portOf(k.Source)); err != nil {
					return err
				}
			}
		}
		if (v.Decision == domain.DecisionNewAsset || v.Decision == domain.DecisionAttach) && !uncorroborated {
			from := store.KeyFromNewAsset
			if v.Decision == domain.DecisionAttach {
				from = store.KeyFromAttach
			}
			// A lapse is the same contest one window later: its keys are
			// inventory, never the credentialed trust root (ADR-096). The
			// review measured 'new_asset' here buying the root with one
			// window of holding tcp/22 against a live host — cheaper than
			// the rotation it preempted, and the forgery that bought MORE.
			if v.Lapsed != uuid.Nil {
				from = store.KeyFromLapsed
			}
			for _, k := range h.keys {
				if k.Type.Strength() < 2 {
					continue // weak keys are the address, held below
				}
				if contradicted(k) {
					continue // recorded above, after the held one was retired
				}
				scanID, err := scanFor(k)
				if err != nil {
					return err
				}
				inserted, err := (store.AssetIdentityKeys{}).Record(ctx, conn, assetID, k, h.seenAt, from, scanID, h.address, portOf(k.Source))
				if err != nil {
					return err
				}
				if !inserted {
					// The value is live already. On this asset that is a
					// re-sighting; on ANOTHER asset it is the key of a host
					// this group did not merge with — one moderate key alone
					// never merges (ADR-007) — and the asset here is left
					// without it. Announced on this asset's timeline rather
					// than silent (measured: a returning host became a third,
					// keyless asset that could never re-merge); the merge
					// question is B40's.
					holder, err := (store.AssetIdentityKeys{}).LiveByValue(ctx, conn, k.Type, k.Value)
					if err != nil && !errors.Is(err, store.ErrNotFound) {
						return err
					}
					if err == nil && holder != assetID {
						if err := (store.AuditEvents{}).Record(ctx, conn, store.AuditEvent{
							ActorType:    store.ActorSystem,
							Action:       "identity.key_held_elsewhere",
							ResourceType: "asset",
							ResourceID:   &assetID,
							Detail: map[string]any{
								"address":  h.address,
								"key_type": string(k.Type),
								"source":   k.Source,
								"held_by":  holder.String(),
								"note":     "this asset was seen with a key another asset holds live; one moderate key alone never merges (ADR-007), so the key stays where it is and this asset holds no key of that type from that service — an operator can merge the two (B39), and grading merge evidence is B40",
							},
						}); err != nil {
							return err
						}
					}
				}
			}
		}

		// A stale contest — items pending at this address for this asset,
		// no contradiction seen for a full window — expires on the attach
		// the domain just allowed (ADR-096): the items close and the address
		// is nobody's prison. The parked observations stay out of the sweep
		// (released, the contradiction re-parked itself and renewed the
		// freeze — measured); what the host still answers is re-derived by
		// this sighting. A fresh contest never reaches here.
		for _, cand := range candidates {
			if cand.AssetID != assetID || cand.HeldAddress != h.address || !cand.PendingContested ||
				domain.ContestFresh(cand, now, AddressWindow) {
				continue
			}
			expired, err := (store.ResolutionQueue{}).CloseExpired(ctx, conn, h.address, assetID, h.seenAt)
			if err != nil {
				return err
			}
			if expired > 0 {
				if err := (store.AuditEvents{}).Record(ctx, conn, store.AuditEvent{
					ActorType:    store.ActorSystem,
					Action:       "identity.contest_expired",
					ResourceType: "asset",
					ResourceID:   &assetID,
					Detail: map[string]any{
						"address":       h.address,
						"items_expired": expired,
						"note":          "no contradicting key seen at the address for a full window while the held host answered; the contest is closed and the host's inventory resumes from this sighting — what was parked during the freeze is not re-derived (ADR-096)",
					},
				}); err != nil {
					return err
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
		//
		// The release matched against is what the asset HOLDS after the ranked
		// writes (ADR-095), not what this sweep's vote decided: a band vote the
		// store refused to record must not be the release the same sweep keys the
		// keyspace on (the review raised a hardy-only CVE on a host held at jammy),
		// and an inferred sweep with no family hint must still match against the
		// exact release a credentialed pass established.
		if held, heldConf, found, err := (store.Assets{}).ReleaseOf(ctx, conn, assetID); err != nil {
			return err
		} else if found {
			release, releaseConf = held, heldConf
		}
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
			// Is a contradiction already parked here? A weak-only sighting
			// then waits with it (ADR-096) rather than walking in on the
			// address alone — the batch-overflow door the review measured.
			pending, err := (store.ResolutionQueue{}).PendingAtAddress(ctx, conn, h.address, id)
			if err != nil {
				return nil, err
			}
			byID[id].PendingContested = pending
			if pending {
				last, _, err := (store.ResolutionQueue{}).ContradictionLastSeen(ctx, conn, h.address, id)
				if err != nil {
					return nil, err
				}
				byID[id].ContradictionLastSeen = last
			}
		}
	}

	out := make([]domain.Candidate, 0, len(byID))
	for _, c := range byID {
		out = append(out, *c)
	}
	// Deterministic: the first candidate names the audit event's resource
	// and the reason's asset; map order made both vary per sweep.
	sort.Slice(out, func(i, j int) bool { return out[i].AssetID.String() < out[j].AssetID.String() })
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
			AssetID: assetID, Port: int(p.Port), Protocol: orDefault(strings.ToLower(strings.TrimSpace(p.Protocol)), "tcp"),
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
	a := domain.AttributeOS(osEvidence(h))
	if a.DistroFamily == "" {
		return "", nil // no attribution: leave the asset's OS columns null
	}
	prov, err := json.Marshal(a.Provenance)
	if err != nil {
		return "", err
	}
	// Inferred: fills an absence, never overwrites an exact read (ADR-095).
	if err := (store.Assets{}).SetAttribution(ctx, conn, assetID, a.DistroFamily, a.DistroRelease, a.Confidence, prov, false); err != nil {
		return "", err
	}
	return a.DistroFamily, nil
}

// osEvidence lifts the per-service OS hints out of a host group, for
// attribution and for ADR-096's OS-agreement fact alike.
func osEvidence(h host) []domain.OSEvidence {
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
	return ev
}

// continuityFor gathers ADR-096's continuity DATA about a contested address
// for the asset holding it. Data only — every rule is domain.rotationFailures.
// Every input is public banner data; the ADR says what that buys and does not.
func (c *Correlator) continuityFor(ctx context.Context, conn *store.Conn, cand domain.Candidate, h host, handover []domain.IdentityKey, now time.Time) (domain.Continuity, error) {
	f := domain.Continuity{Keys: map[string]domain.KeyContinuity{}}
	since := now.Add(-store.SightingWindow)
	assetID := cand.AssetID

	for _, k := range handover {
		var kc domain.KeyContinuity
		// The newcomer's scans: the parked ones plus this one.
		scans, first, _, err := (store.ResolutionQueue{}).KeyScansPending(ctx, conn, k.Type, k.Value, h.address, since)
		if err != nil {
			return f, err
		}
		seen := map[uuid.UUID]bool{}
		for _, id := range scans {
			seen[id] = true
		}
		for _, o := range h.obs {
			if o.ID == k.ObservationID {
				id, err := (store.Jobs{}).ScanIDForTask(ctx, conn, o.TaskID)
				if err != nil {
					return f, err
				}
				if id != uuid.Nil {
					seen[id] = true
				}
				break
			}
		}
		kc.NewKeyScans = len(seen)
		if first.IsZero() {
			first = h.seenAt
		}
		kc.NewKeyFirstSeen = first

		// The held key of the same service: its sighting recorded on an
		// attach, and its sightings parked with a contested group — the
		// latest of either.
		port := portOf(k.Source)
		if last, found, err := (store.AssetIdentityKeys{}).LastSeenAt(ctx, conn, assetID, k.Type, port, h.address); err != nil {
			return f, err
		} else if found {
			kc.HeldKeySighted, kc.HeldKeyLastSeen = true, last
		}
		for _, held := range cand.Keys {
			if held.Type != k.Type || held.Source != k.Source {
				continue
			}
			if _, _, last, err := (store.ResolutionQueue{}).KeyScansPending(ctx, conn, held.Type, held.Value, h.address, since); err != nil {
				return f, err
			} else if !last.IsZero() {
				kc.HeldKeySighted = true
				if last.After(kc.HeldKeyLastSeen) {
					kc.HeldKeyLastSeen = last
				}
			}
		}

		// Live on another asset already?
		holder, err := (store.AssetIdentityKeys{}).LiveByValue(ctx, conn, k.Type, k.Value)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return f, err
		}
		kc.NewKeyHeldElsewhere = err == nil && holder != assetID
		f.Keys[k.Source] = kc
	}

	held, err := (store.Services{}).ProductsSince(ctx, conn, assetID, since)
	if err != nil {
		return f, err
	}
	for _, s := range held {
		f.HeldServices = append(f.HeldServices, domain.ServiceSeen{Port: s.Port, Protocol: s.Protocol, Product: s.Product})
	}
	for _, o := range h.obs {
		if o.Type != "service" {
			continue
		}
		var p servicePayload
		if err := json.Unmarshal(o.Payload, &p); err != nil || p.Port == 0 {
			continue
		}
		proto, ok := normProtocol(p.Protocol)
		if !ok {
			continue
		}
		f.ObservedServices = append(f.ObservedServices, domain.ServiceSeen{Port: int(p.Port), Protocol: proto, Product: p.Product})
	}
	if f.HeldFamily, err = (store.Assets{}).FamilyOf(ctx, conn, assetID); err != nil {
		return f, err
	}
	f.ObservedFamily = domain.AttributeOS(osEvidence(h)).DistroFamily
	return f, nil
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
	// Inferred: fills an absence, never overwrites an exact read (ADR-095).
	if err := (store.Assets{}).SetRelease(ctx, conn, assetID, res.Release, res.Confidence, prov, false); err != nil {
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
	Family  string    // os-release ID, e.g. "ubuntu"
	Release string    // release key (codename, or ID-major for rpm)
	ReadAt  time.Time // when the host was read — the age an exact attribution carries (ADR-095)
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
			// Core's site of the token grammar (ADR-095): the engine refuses a
			// read outside it, and a scan point running an older or altered
			// build must not be able to pin what the engine would have refused.
			if !domain.ReleaseTokenValid(p.Family) || !domain.ReleaseTokenValid(p.Release) {
				continue
			}
			return credentialedFacts{Family: p.Family, Release: p.Release, ReadAt: o.ObservedAt}, true
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
	// read_at is the age an exact attribution carries (ADR-095): a host that
	// stops answering credentialed keeps its last exact value, and the
	// operator sees how old it is rather than watching it revert to a guess.
	famProv, err := json.Marshal(map[string]any{
		"source":  "os-release",
		"family":  f.Family,
		"read_at": f.ReadAt.UTC().Format(time.RFC3339),
		"basis":   "exact /etc/os-release ID read on the host; outranks service-inferred attribution (ADR-089)",
	})
	if err != nil {
		return "", 0, err
	}
	if err := (store.Assets{}).SetAttribution(ctx, conn, assetID, f.Family, &rel, 1.0, famProv, true); err != nil {
		return "", 0, err
	}
	relProv, err := json.Marshal(map[string]any{
		"source":  "package_manager",
		"release": f.Release,
		"read_at": f.ReadAt.UTC().Format(time.RFC3339),
		"basis":   "exact release read from /etc/os-release; outranks band voting (ADR-076/077/089)",
	})
	if err != nil {
		return "", 0, err
	}
	if err := (store.Assets{}).SetRelease(ctx, conn, assetID, &rel, 1.0, relProv, true); err != nil {
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

// portOf reads the port from a key's source ("22/tcp"); 0 when there is none,
// which Record treats as "no occasion to count".
func portOf(source string) int {
	i := strings.IndexByte(source, '/')
	if i <= 0 {
		return 0
	}
	n, err := strconv.Atoi(source[:i])
	if err != nil || n <= 0 || n > 65535 {
		return 0
	}
	return n
}
