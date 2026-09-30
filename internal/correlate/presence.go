package correlate

import (
	"context"
	"log/slog"
	"time"

	"github.com/effaaykhan/cvap/internal/domain"
	"github.com/effaaykhan/cvap/internal/store"
)

// DecidePresence judges, for one tenant, which addresses hold a host and which
// carry the signature of one device answering for a range (ADR-108).
//
// WHY THIS IS NOT PART OF THE SWEEP. The sweep's unit is a HOST — identity is a
// property of a host and the evidence is spread across several observations. The
// presence signal is the opposite shape: it only exists across a POPULATION,
// because a single address cannot tell you whether the thing answering on 5060 is
// a soft switch or a firewall wearing 473 addresses. Folding it into the per-host
// transaction would hand the rule one address and ask it to see a range.
//
// It also runs AFTER correlation rather than before: the discriminator is whether
// a service ever identified itself, and identification is what the sweep
// produces. Running first would judge every address on an empty evidence set and
// suppress the estate.
func (c *Correlator) DecidePresence(ctx context.Context, tenant store.TenantID) (store.PresenceSummary, error) {
	var sum store.PresenceSummary
	policy := domain.DefaultResponderPolicy()

	// One transaction, on the bulk budget (ADR-101): this reads every live address
	// and every service for the tenant, which is a sweep-shaped read rather than
	// an operator-shaped one. Gathering and deciding in the SAME transaction
	// matters — a verdict computed from one population and written against
	// another is a verdict about a network that no longer existed when it landed.
	err := c.db.WriteWithin(ctx, tenant, store.BulkBudget, func(ctx context.Context, conn *store.Conn) error {
		pop, evidence, err := (store.Presence{}).GatherEvidence(ctx, conn)
		if err != nil {
			return err
		}
		if len(evidence) == 0 {
			return nil
		}
		sum, err = (store.Presence{}).RecordVerdicts(ctx, conn, pop, evidence, policy, time.Now())
		return err
	})
	if err != nil {
		return store.PresenceSummary{}, err
	}

	// Logged because ADR-108 decision 6 requires the suppression to be STATED,
	// and an operator who has not opened the console yet still deserves to know
	// that four fifths of their estate was judged not to exist. The counts are
	// the claim; the reason per address is in the row.
	c.log.InfoContext(ctx, "address presence decided",
		slog.String("tenant_id", tenant.String()),
		slog.Int("present", sum.Present),
		slog.Int("responder", sum.Responder),
		slog.Int("unknown", sum.Unknown),
		slog.Float64("ubiquity_fraction", policy.UbiquityFraction),
		slog.Int("min_population", policy.MinPopulation))
	return sum, nil
}
