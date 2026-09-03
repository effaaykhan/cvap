package dispatch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/store"
	"github.com/effaaykhan/cvap/internal/target"
)

// Planning: a scan's declared targets become jobs and tasks.
//
// ============================================================================
// This is the site where canonicalisation happens (ADR-044).
// ============================================================================
//
// Everything downstream sees ONE spelling per host. The scan point re-computes
// the same function and compares, which is a disagreement detector rather than a
// second normalisation — see internal/target.Matches, and ADR-044 on why
// validating the form instead would accept a canonical form of the wrong host.

// MaxAddressesPerTarget bounds what one declared target may expand to.
//
// 65,536 — a /16 of IPv4. The bound exists because a prefix does not survive
// decomposition: it is expanded to addresses, so that an exclusion of one host
// inside a scanned range is enforced per host rather than having to refuse the
// whole range.
//
// The alternative was to keep the prefix as a task target and let the engine
// enumerate it, with the runtime authorising each address on the send path. That
// works only for as long as every engine actually asks, and the failure mode is
// silent: an engine that swept its assigned range directly would walk past every
// exclusion inside it, and nothing in the observation stream would say so.
// Expanding here makes the exclusion a property of what was planned rather than
// of how an engine behaves.
//
// The cost is real and worth naming: a /8 sweep is refused rather than planned.
// An operator who wants one writes 256 targets, which is tedious and honest.
const MaxAddressesPerTarget = 65536

// PlanBatchLimit bounds how many scans one tenant may have planned in one sweep
// pass.
//
// Separate from Sweeper.BatchLimit, which bounds lease expiry, because the two
// bound different costs: one is rows examined, the other is rows written, and
// four scans of a /16 in one pass is a quarter of a million inserts before the
// next tenant's leases are looked at.
const PlanBatchLimit = 4

// ErrTargetTooLarge means a declared target expands past MaxAddressesPerTarget.
var ErrTargetTooLarge = errors.New("dispatch: target expands to more addresses than one scan may plan")

// ErrTargetNotCanonical means a declared target could not be reduced to a
// canonical form (ADR-040, ADR-044).
var ErrTargetNotCanonical = errors.New("dispatch: target has no canonical form")

// PlanScan turns a pending scan into queued jobs.
//
// It refuses the whole scan rather than planning the part of it that works. A
// scan that silently dropped an unauthorised or unparseable target would report
// a clean run over coverage it did not have, which is the failure ADR-040 chose
// job-level refusal for and the same position ErrTooManyTasks takes.
func PlanScan(ctx context.Context, db *store.DB, tenant store.TenantID, scanID uuid.UUID, engine store.Engine, reassignSafe bool) (int, error) {
	var planned int

	err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		// pending -> planning first, in the UPDATE's own predicate. A scan
		// cancelled between a read and this write must not be planned, and the
		// predicate is what makes that impossible rather than unlikely.
		if err := (store.Scans{}).SetStatus(ctx, c, scanID, []store.ScanStatus{store.ScanPending}, store.ScanPlanning); err != nil {
			return fmt.Errorf("scan %s is not plannable: %w", scanID, err)
		}

		targets, err := (store.Scans{}).Targets(ctx, c, scanID)
		if err != nil {
			return err
		}
		if len(targets) == 0 {
			return fmt.Errorf("scan %s has no targets", scanID)
		}

		var tasks []store.PlannedTask
		for _, t := range targets {
			// Execution-plan §8 risk 6. The column defaults false and this is
			// the gate: an unauthorised target is not skipped, it stops the
			// scan, because a scan that quietly omitted one would report
			// coverage of a network nobody agreed to.
			if !t.Authorized {
				return fmt.Errorf("%w: target %s (%s)", store.ErrTargetNotAuthorized, t.ID, t.Value)
			}

			expanded, err := expand(t.Value)
			if err != nil {
				return fmt.Errorf("target %s: %w", t.ID, err)
			}
			id := t.ID
			for _, v := range expanded {
				tasks = append(tasks, store.PlannedTask{Target: v, TargetID: &id})
			}
		}

		// One job for now. Splitting across scan points is a scheduling
		// decision this session does not make; MaxTasksPerAssignment already
		// refuses a job too large to deliver, which is the bound that matters.
		if _, err := (store.Scans{}).Plan(ctx, c, scanID, engine, reassignSafe, tasks); err != nil {
			return err
		}
		planned = len(tasks)

		return (store.Scans{}).SetStatus(ctx, c, scanID, []store.ScanStatus{store.ScanPlanning}, store.ScanRunning)
	})

	return planned, err
}

// expand reduces one declared target to the canonical task targets it names.
//
// An address or a hostname is itself. A prefix becomes every address it
// contains, which is what makes a per-host exclusion enforceable against a range
// scan — see MaxAddressesPerTarget.
func expand(declared string) ([]string, error) {
	c, err := target.Canonicalise(declared)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTargetNotCanonical, err)
	}

	switch c.Kind {
	case target.KindAddress, target.KindHostname:
		return []string{c.Value}, nil

	case target.KindPrefix:
		n := hostCount(c.Prefix)
		if n == 0 || n > MaxAddressesPerTarget {
			return nil, fmt.Errorf("%w: %s covers %s addresses, the limit is %d",
				ErrTargetTooLarge, c.Value, countString(c.Prefix), MaxAddressesPerTarget)
		}
		// EVERY address, including the network and directed-broadcast
		// addresses of an IPv4 prefix. Decided rather than overlooked.
		//
		// The argument for skipping them is amplification: a probe to a
		// directed broadcast can be answered by every host behind it. The
		// argument against is that routers have dropped directed broadcasts by
		// default since RFC 2644 in 1999, that a /24 inside a larger supernet
		// has ordinary hosts at .0 and .255, and that skipping them is
		// under-scanning which reports as a clean run — the failure this
		// codebase weighs heaviest. Rate limiting is the control for
		// amplification, and it is applied per target at both sites already.
		out := make([]string, 0, n)
		for a := c.Prefix.Addr(); c.Prefix.Contains(a); a = a.Next() {
			// Each expanded address goes through Canonicalise rather than
			// String(), so the strings written to scan_tasks.task_target are
			// produced by the same function the scan point will re-run. A
			// netip.Addr formatted directly would agree today and would be a
			// second producer of canonical forms tomorrow.
			e, err := target.Canonicalise(a.String())
			if err != nil {
				return nil, fmt.Errorf("%w: %s expanded to %s: %w", ErrTargetNotCanonical, c.Value, a, err)
			}
			out = append(out, e.Value)
			if !a.Next().IsValid() {
				break
			}
		}
		return out, nil

	default:
		return nil, fmt.Errorf("%w: unclassifiable %q", ErrTargetNotCanonical, declared)
	}
}

// hostCount is the number of addresses in a prefix, or 0 when that number does
// not fit in an int.
//
// Deliberately saturating rather than approximate: an IPv6 /64 has 2^64
// addresses and any arithmetic that produced a small number for it would turn a
// refusal into an expansion that never terminates.
func hostCount(p netip.Prefix) int {
	bits := p.Addr().BitLen() - p.Bits()
	if bits < 0 || bits > 31 {
		return 0
	}
	return 1 << uint(bits)
}

// countString describes a prefix's size for an error message, without
// pretending to compute one that does not fit.
func countString(p netip.Prefix) string {
	bits := p.Addr().BitLen() - p.Bits()
	if bits > 31 {
		return fmt.Sprintf("2^%d", bits)
	}
	return fmt.Sprintf("%d", 1<<uint(bits))
}

// PlanPending plans every pending scan for one tenant.
//
// This is what the sweeper calls, and it is why PlanScan has a production caller
// at all: a scan created through the operator API sits `pending` until something
// decomposes it, and "something" is a periodic pass rather than the request
// handler. Planning a /16 writes 65,536 rows, which is not work to do inside an
// HTTP request while the operator's browser waits.
//
// Each scan is planned in its OWN transaction. One scan that cannot be planned
// must not roll back the ones that could — and the failures here are permanent
// rather than transient, so a batch that failed as a unit would starve every
// scan behind the bad one.
func PlanPending(ctx context.Context, db *store.DB, log *slog.Logger, tenant store.TenantID, limit int) {
	var pending []uuid.UUID
	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		pending, err = (store.Scans{}).PendingIDs(ctx, c, limit)
		return err
	}); err != nil {
		log.ErrorContext(ctx, "plan: list pending scans", "tenant_id", tenant.String(), "error", err)
		return
	}

	for _, scanID := range pending {
		if ctx.Err() != nil {
			return
		}
		engine, reassignSafe, err := engineFor(ctx, db, tenant, scanID)
		if err == nil {
			var n int
			n, err = PlanScan(ctx, db, tenant, scanID, engine, reassignSafe)
			if err == nil {
				log.InfoContext(ctx, "scan planned",
					"tenant_id", tenant.String(), "scan_id", scanID.String(),
					"engine", string(engine), "tasks", n)
				continue
			}
		}

		// A planning failure is TERMINAL and says so in the audit log.
		//
		// Every reason planning refuses — an unattested target, a target with no
		// canonical form, a range past the bound — is something an operator must
		// change. Retrying would fail identically forever while looking like
		// activity, and a scan stuck 'planning' with nothing moving is the state
		// an operator cannot tell from a working one.
		log.ErrorContext(ctx, "scan planning failed",
			"tenant_id", tenant.String(), "scan_id", scanID.String(), "error", err)
		if ferr := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
			return (store.Scans{}).Fail(ctx, c, scanID, err.Error())
		}); ferr != nil {
			log.ErrorContext(ctx, "scan planning failure could not be recorded",
				"tenant_id", tenant.String(), "scan_id", scanID.String(), "error", ferr)
		}
	}
}

// engineFor maps a scan's type to the engine that runs it.
//
// A closed map rather than a cast, even though scans.scan_type is deliberately
// free text (0005): the column is open because engines are extensible, and this
// is Core deciding what it can actually plan. An unrecognised type fails the
// scan with a message naming it, rather than queueing a job for an engine kind
// no scan point declares — which would sit unclaimed forever and look like a
// dispatch problem.
func engineFor(ctx context.Context, db *store.DB, tenant store.TenantID, scanID uuid.UUID) (store.Engine, bool, error) {
	var scan *store.Scan
	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		scan, err = (store.Scans{}).Get(ctx, c, scanID)
		return err
	}); err != nil {
		return "", false, err
	}

	// reassign_safe is false for every entry, and that is ADR-012's default
	// rather than an oversight: duplicating work is assumed harmful until a job
	// type is shown to be safe to duplicate. Discovery looks obviously
	// idempotent and is not — a second sweep of the same range is a second set
	// of packets at a host that may be fragile.
	switch scan.ScanType {
	case "discovery":
		return store.EngineDiscovery, false, nil
	case "fingerprint":
		return store.EngineFingerprint, false, nil
	case "rules":
		return store.EngineRules, false, nil
	default:
		return "", false, fmt.Errorf("%w: scan_type %q", ErrUnplannableScanType, scan.ScanType)
	}
}

// ErrUnplannableScanType means Core has no engine for a scan's type.
var ErrUnplannableScanType = errors.New("dispatch: no engine plans this scan type")
