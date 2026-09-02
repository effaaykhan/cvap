package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ObservationType is the closed set from the ERD (ADR-006).
//
// The wire carries this as an open string, deliberately: engines are extensible
// by design (ADR-027) and a closed wire enum would make every new observation
// type a protocol change. Core validates the incoming string against this set
// at ingest and returns REJECTED_MALFORMED for an unknown one. That validation
// is the producer/consumer agreement — see ValidObservationType.
type ObservationType string

const (
	ObsHost    ObservationType = "host"
	ObsPort    ObservationType = "port"
	ObsService ObservationType = "service"
	ObsBanner  ObservationType = "banner"
	ObsPackage ObservationType = "package"
	ObsConfig  ObservationType = "config"

	// ObsVerdict carries the outcome of a request-coupled rule evaluated at the
	// scan point (ADR-013): rule_id, outcome, and the request/response pair. It
	// is still an observation — Core constructs the Finding from it. A scan
	// point reporting a verdict is reporting what it saw, not writing a finding.
	ObsVerdict ObservationType = "verdict"
)

var validObservationTypes = map[ObservationType]struct{}{
	ObsHost: {}, ObsPort: {}, ObsService: {}, ObsBanner: {},
	ObsPackage: {}, ObsConfig: {}, ObsVerdict: {},
}

// ValidObservationType is the ingest-time check that closes the open wire
// string against the ERD enum. An unknown value is REJECTED_MALFORMED.
func ValidObservationType(s string) bool {
	_, ok := validObservationTypes[ObservationType(s)]
	return ok
}

// IngestState mirrors observation_ingest_state.
type IngestState string

const (
	// IngestPending is where every observation starts.
	//
	// A submission arrives in chunks and its lease epoch can be superseded
	// midway. If chunks landed as accepted, the finding pipeline — which filters
	// exactly on that — could read chunk 0 before chunk 5 revealed the
	// supersession. Quarantining retrospectively narrows that window; it does
	// not close it.
	//
	// Landing pending closes it. The pipeline filters `accepted`, so an
	// in-flight submission is invisible to it without the pipeline having to
	// know submissions exist: no join to remember, and no window.
	IngestPending IngestState = "pending"

	// IngestAccepted: promoted by the terminal ack, in the same transaction as
	// the final epoch check.
	IngestAccepted IngestState = "accepted"

	// IngestQuarantined: stored, withheld from the finding pipeline,
	// operator-surfaced (ADR-026).
	IngestQuarantined IngestState = "quarantined"
)

// The ratchet: pending may be promoted once; accepted and quarantined are
// terminal. Enforced by a trigger in migration 0020 rather than by convention,
// because the finding pipeline runs as the same database role as ingest — a
// grant cannot express "ingest may set this and the pipeline may not", and a
// ratchet can, since un-quarantining is not an operation anything legitimately
// performs.

// Observation is what a scan point saw. Immutable once written, and ephemeral:
// partitioned monthly with 90-day default retention, pruned by dropping a
// partition (ADR-016).
//
// Anything that must outlive an observation is COPIED at the moment it becomes
// load-bearing — merge evidence into asset_identity_keys, finding and verdict
// payloads into evidence — never referenced. That rule is why evidence.
// observation_id is a soft reference with no FK.
type Observation struct {
	ID           uuid.UUID
	SubmissionID string
	TaskID       uuid.UUID
	ScanPointID  uuid.UUID

	// ZoneID is the vantage point, and the reason assets have no zone column
	// (ADR-008). Self-asserted on the wire and MUST be validated by Core against
	// the zones the authenticated scan point was enrolled into: a scan point
	// free to name its own zone could rewrite the derived exposure of every
	// asset it reports. A mismatch is quarantined, never silently re-zoned.
	ZoneID uuid.UUID

	// AssetID is nil until correlation resolves it. That is the normal state on
	// arrival — a scan point never resolves an asset (ADR-006).
	AssetID *uuid.UUID

	Type        ObservationType
	Payload     []byte // jsonb
	Confidence  *float64
	ObservedAt  time.Time
	IngestState IngestState
}

type Observations struct{}

var errBadObservationType = errors.New("store: unknown observation_type")

// Insert writes one observation.
//
// submissionID is required and is a real FK to result_submissions: an
// observation with no submission cannot be deduplicated, and idempotency has to
// be at the boundary (ADR-026). ingestState is set here at INSERT — normally
// IngestPending, promoted once by the terminal ack. It is a ratchet, not an
// immutable column: migration 0020's trigger permits pending -> accepted or
// quarantined and refuses every transition out of a terminal state. An earlier
// version of this comment said the column was never updated, which was true
// before 0020 and is the kind of stale invariant a reader trusts.
func (Observations) Insert(ctx context.Context, c *Conn, o Observation, state IngestState) error {
	if !ValidObservationType(string(o.Type)) {
		return fmt.Errorf("%w: %q", errBadObservationType, o.Type)
	}

	const q = `
		INSERT INTO observations
		    (observation_id, tenant_id, submission_id, task_id, scan_point_id,
		     zone_id, asset_id, observation_type, payload, confidence,
		     observed_at, ingest_state)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	_, err := c.Exec(ctx, q, o.ID, c.Tenant().UUID(), o.SubmissionID, o.TaskID,
		o.ScanPointID, o.ZoneID, o.AssetID, string(o.Type), o.Payload,
		o.Confidence, o.ObservedAt, string(state))
	return mapError(err)
}

// InsertBatch writes many observations in one round trip.
//
// The ingest target is 5,000 observations/sec (execution-plan §5), so a round
// trip per row is not affordable. pgx.Batch rather than CopyFrom: COPY bypasses
// the per-row machinery that RLS WITH CHECK policies hang off, and this is the
// one table where a write landing outside its tenant would be least visible.
// A multi-row INSERT batch takes the same policy path as a single insert.
//
// The whole batch runs inside the caller's transaction, so a failure anywhere
// rolls the lot back — which is what you want for a chunk: a half-ingested chunk
// that the scan point believes was accepted is worse than a retried one.
func (Observations) InsertBatch(ctx context.Context, c *Conn, obs []Observation, state IngestState) error {
	if len(obs) == 0 {
		return nil
	}
	for i := range obs {
		if !ValidObservationType(string(obs[i].Type)) {
			return fmt.Errorf("%w: %q at index %d", errBadObservationType, obs[i].Type, i)
		}
	}

	const q = `
		INSERT INTO observations
		    (observation_id, tenant_id, submission_id, task_id, scan_point_id,
		     zone_id, asset_id, observation_type, payload, confidence,
		     observed_at, ingest_state)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`

	batch := &Batch{}
	tenant := c.Tenant().UUID()
	for _, o := range obs {
		batch.Queue(q, o.ID, tenant, o.SubmissionID, o.TaskID, o.ScanPointID,
			o.ZoneID, o.AssetID, string(o.Type), o.Payload, o.Confidence,
			o.ObservedAt, string(state))
	}

	res := c.SendBatch(ctx, batch)
	defer func() { _ = res.Close() }()

	for i := range obs {
		if _, err := res.Exec(); err != nil {
			return fmt.Errorf("observation %d of %d: %w", i+1, len(obs), mapError(err))
		}
	}
	return mapError(res.Close())
}

// The read paths below all filter ingest_state = 'accepted'.
//
// Quarantined rows are retained deliberately (ADR-026): they are the record of
// what a job touched, and the operator escalation depends on them existing. They
// are NOT pipeline input. Anything reading observations to derive assets or
// findings must not see them, which is why the predicate is in the query rather
// than left to the caller — a filter the caller can forget is a filter that will
// be forgotten. ListQuarantined is the deliberate exception, named so.

const observationColumns = `
	observation_id, submission_id, task_id, scan_point_id, zone_id, asset_id,
	observation_type, payload, confidence, observed_at, ingest_state`

func scanObservations(rows Rows) ([]Observation, error) {
	defer rows.Close()
	var out []Observation
	for rows.Next() {
		var o Observation
		if err := rows.Scan(&o.ID, &o.SubmissionID, &o.TaskID, &o.ScanPointID,
			&o.ZoneID, &o.AssetID, &o.Type, &o.Payload, &o.Confidence,
			&o.ObservedAt, &o.IngestState); err != nil {
			return nil, mapError(err)
		}
		out = append(out, o)
	}
	return out, mapError(rows.Err())
}

// ListByTask returns accepted observations for one task, oldest first.
//
// Backed by the (task_id, observed_at) index. Task is the unit of observation
// attribution (ADR-011).
func (Observations) ListByTask(ctx context.Context, c *Conn, taskID uuid.UUID, limit int) ([]Observation, error) {
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}

	q := `SELECT ` + observationColumns + `
		    FROM observations
		   WHERE tenant_id = $1 AND task_id = $2 AND ingest_state = 'accepted'
		   ORDER BY observed_at
		   LIMIT $3`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), taskID, limit)
	if err != nil {
		return nil, mapError(err)
	}
	return scanObservations(rows)
}

// ListUnresolved returns accepted observations that correlation has not yet
// attached to an asset, within a time window.
//
// The window is required, not optional. observations is the largest table in
// the system and partitioned by observed_at, so a query without a time
// predicate scans every live partition (ADR-016).
func (Observations) ListUnresolved(ctx context.Context, c *Conn, since, until time.Time, limit int) ([]Observation, error) {
	if since.IsZero() || until.IsZero() {
		return nil, errors.New("store: ListUnresolved needs a bounded time window; observations is partitioned by observed_at")
	}
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}

	q := `SELECT ` + observationColumns + `
		    FROM observations
		   WHERE tenant_id = $1
		     AND observed_at >= $2 AND observed_at < $3
		     AND asset_id IS NULL
		     AND ingest_state = 'accepted'
		   ORDER BY observed_at
		   LIMIT $4`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), since, until, limit)
	if err != nil {
		return nil, mapError(err)
	}
	return scanObservations(rows)
}

// ListByAsset returns accepted observations resolved to one asset, newest first,
// within a window. The window is required for the same reason as above.
func (Observations) ListByAsset(ctx context.Context, c *Conn, assetID uuid.UUID, since, until time.Time, limit int) ([]Observation, error) {
	if since.IsZero() || until.IsZero() {
		return nil, errors.New("store: ListByAsset needs a bounded time window; observations is partitioned by observed_at")
	}
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}

	q := `SELECT ` + observationColumns + `
		    FROM observations
		   WHERE tenant_id = $1 AND asset_id = $2
		     AND observed_at >= $3 AND observed_at < $4
		     AND ingest_state = 'accepted'
		   ORDER BY observed_at DESC
		   LIMIT $5`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), assetID, since, until, limit)
	if err != nil {
		return nil, mapError(err)
	}
	return scanObservations(rows)
}

// ListQuarantined is the operator queue, and the ONLY read here that returns
// quarantined rows. It exists because those rows must be surfaced to a human,
// never dropped. Do not use it as pipeline input.
func (Observations) ListQuarantined(ctx context.Context, c *Conn, since, until time.Time, limit int) ([]Observation, error) {
	if since.IsZero() || until.IsZero() {
		return nil, errors.New("store: ListQuarantined needs a bounded time window; observations is partitioned by observed_at")
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	q := `SELECT ` + observationColumns + `
		    FROM observations
		   WHERE tenant_id = $1
		     AND observed_at >= $2 AND observed_at < $3
		     AND ingest_state = 'quarantined'
		   ORDER BY observed_at DESC
		   LIMIT $4`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), since, until, limit)
	if err != nil {
		return nil, mapError(err)
	}
	return scanObservations(rows)
}

// Promote moves every pending observation in a submission to its terminal state.
//
// One statement, and it must run in the SAME transaction as the final epoch
// check — that is what makes the disposition and the decision atomic. A
// submission promoted to accepted while its epoch was already superseded would
// put results from a fenced-off scan point into the finding pipeline.
//
// The WHERE clause names pending explicitly rather than relying on the trigger
// to refuse the rest: the trigger is the backstop, and a statement that depends
// on its backstop to be correct is a statement that raises in normal operation.
func (Observations) Promote(ctx context.Context, c *Conn, submissionID string, to IngestState) (int64, error) {
	if to != IngestAccepted && to != IngestQuarantined {
		return 0, fmt.Errorf("store: cannot promote observations to %q; pending is the "+
			"starting state and only accepted or quarantined are terminal", to)
	}

	const q = `
		UPDATE observations
		   SET ingest_state = $3
		 WHERE tenant_id = $1
		   AND submission_id = $2
		   AND ingest_state = 'pending'`

	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), submissionID, string(to))
	if err != nil {
		return 0, mapError(err)
	}
	return tag.RowsAffected(), nil
}

// PendingOlderThan counts observations still pending past a cutoff.
//
// The metric for the consequence the pending state creates: an upload abandoned
// midway leaves its rows pending forever. That is correct — the results were
// never attested complete, and deleting them would discard the record of what a
// job touched (ADR-026) — but "correct and unbounded" needs to be visible, or
// the first anyone knows of a broken ingest is a finding count that stopped
// moving.
//
// Bounded window, like every other read here: observations is partitioned by
// observed_at.
func (Observations) PendingOlderThan(ctx context.Context, c *Conn, since, cutoff time.Time) (int64, error) {
	const q = `
		SELECT count(*)
		  FROM observations
		 WHERE tenant_id = $1
		   AND observed_at >= $2 AND observed_at < $3
		   AND ingest_state = 'pending'`

	var n int64
	if err := c.QueryRow(ctx, q, c.Tenant().UUID(), since, cutoff).Scan(&n); err != nil {
		return 0, mapError(err)
	}
	return n, nil
}

// Resolve attaches an observation to an asset. Correlation's write.
//
// This is the one legitimate UPDATE on an immutable table: the observation's
// content is unchanged, only Core's conclusion about which asset it belongs to.
// Nothing else here may update an observation, and ingest_state in particular
// must not be.
func (Observations) Resolve(ctx context.Context, c *Conn, observationID uuid.UUID, observedAt time.Time, assetID uuid.UUID) error {
	// observed_at is in the predicate because it is the partition key: without
	// it Postgres must touch every live partition to find one row.
	const q = `
		UPDATE observations
		   SET asset_id = $4
		 WHERE tenant_id = $1 AND observation_id = $2 AND observed_at = $3`

	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), observationID, observedAt, assetID)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
