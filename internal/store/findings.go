package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Findings: the observed instances (ADR-009). Written by Core from observations,
// never by a scan point (ADR-006).

// Finding is one row, as the pipeline writes it.
type Finding struct {
	AssetID    uuid.UUID
	RuleID     uuid.UUID
	DedupKey   string
	Locator    string
	Severity   string
	Confidence float64
	Summary    string
}

// FindingEvidence is what a human verifies the finding by, copied from the
// observation (ADR-016): it must outlive the observation partition.
type FindingEvidence struct {
	ObservationID uuid.UUID
	Type          string // evidence_type enum
	Data          map[string]any
	CapturedAt    time.Time
}

// Exposure is one vantage point that saw the issue (ADR-008). The same finding
// carries several; each is a finding_exposure row.
type Exposure struct {
	ZoneID uuid.UUID
}

type Findings struct{}

// Upsert writes a finding by its dedup key, refreshing it if it already exists.
//
// ============================================================================
// Keyed on dedup_key, so a finding persists across scans — its age, its triage
// state, its history all survive a re-scan (ADR-010).
// ============================================================================
//
// A finding already `remediated` or `closed` that fires again REOPENS to `open`:
// the issue an operator marked fixed is back, and that is a state transition
// worth a history row, which the caller writes. `false_positive` and
// `accepted_risk` are NOT reopened — those are an operator's judgement that the
// finding does not matter, and re-detecting the same true fact should not
// undo it every scan.
//
// Returns the finding id and whether the status was reopened, so the caller can
// record the transition.
func (Findings) Upsert(ctx context.Context, c *Conn, f Finding, seenAt time.Time) (id uuid.UUID, reopened bool, err error) {
	// The reopen signal needs the status BEFORE the upsert, which RETURNING
	// cannot show cleanly, so read the prior row first — in the same
	// transaction, so nothing changes it between the read and the write.
	var priorStatus string
	existed := true
	{
		const sel = `SELECT status FROM findings WHERE tenant_id = $1 AND dedup_key = $2`
		row := c.QueryRow(ctx, sel, c.Tenant().UUID(), f.DedupKey)
		if e := row.Scan(&priorStatus); e != nil {
			existed = false
		}
	}

	const ins = `
		INSERT INTO findings (
		    tenant_id, asset_id, rule_id, source, dedup_key, instance_locator,
		    severity, confidence, status, first_seen, last_seen)
		VALUES ($1, $2, $3, 'network', $4, nullif($5,''), $6, $7, 'open', $8, $8)
		ON CONFLICT (tenant_id, dedup_key) DO UPDATE SET
		    severity   = excluded.severity,
		    confidence = excluded.confidence,
		    last_seen  = excluded.last_seen,
		    status = CASE
		        WHEN findings.status IN ('remediated', 'closed') THEN 'open'
		        ELSE findings.status
		    END
		RETURNING finding_id`

	if e := c.QueryRow(ctx, ins, c.Tenant().UUID(), f.AssetID, f.RuleID, f.DedupKey,
		f.Locator, f.Severity, f.Confidence, seenAt).Scan(&id); e != nil {
		return uuid.Nil, false, mapError(e)
	}

	reopened = existed && (priorStatus == "remediated" || priorStatus == "closed")
	return id, reopened, nil
}

// SetExposure replaces the finding's exposure set with the zones passed.
//
// Replace rather than merge, because the exposure set is a statement about THIS
// scan: a management port that used to be reachable from the DMZ and now is not
// should lose that exposure, and a merge would keep it forever. A finding with
// no exposures is possible in principle and is not written — every finding this
// engine raises came from an observation that had a zone.
func (Findings) SetExposure(ctx context.Context, c *Conn, findingID uuid.UUID, zones []uuid.UUID, at time.Time) error {
	const del = `DELETE FROM finding_exposure WHERE tenant_id = $1 AND finding_id = $2`
	if _, err := c.Exec(ctx, del, c.Tenant().UUID(), findingID); err != nil {
		return mapError(err)
	}
	const ins = `
		INSERT INTO finding_exposure (tenant_id, finding_id, zone_id, last_confirmed)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant_id, finding_id, zone_id) DO UPDATE SET last_confirmed = excluded.last_confirmed`
	for _, z := range zones {
		if _, err := c.Exec(ctx, ins, c.Tenant().UUID(), findingID, z, at); err != nil {
			return mapError(err)
		}
	}
	return nil
}

// ReplaceEvidence sets the finding's evidence to exactly what was passed.
//
// Replace, because evidence describes the current instance: the certificate that
// is expired NOW, not the one that was expired last month. The observation id is
// a soft reference with no FK — the observation partition drops on the 90-day
// clock (ADR-016) — which is why data is COPIED here rather than joined.
func (Findings) ReplaceEvidence(ctx context.Context, c *Conn, findingID uuid.UUID, ev []FindingEvidence) error {
	const del = `DELETE FROM evidence WHERE tenant_id = $1 AND finding_id = $2`
	if _, err := c.Exec(ctx, del, c.Tenant().UUID(), findingID); err != nil {
		return mapError(err)
	}
	const ins = `
		INSERT INTO evidence (tenant_id, finding_id, observation_id, evidence_type, data, captured_at)
		VALUES ($1, $2, $3, $4, $5, $6)`
	for _, e := range ev {
		data, err := json.Marshal(e.Data)
		if err != nil {
			return mapError(err)
		}
		var obs any
		if e.ObservationID != uuid.Nil {
			obs = e.ObservationID
		}
		if _, err := c.Exec(ctx, ins, c.Tenant().UUID(), findingID, obs, e.Type, data, e.CapturedAt); err != nil {
			return mapError(err)
		}
	}
	return nil
}

// RecordTransition writes a finding_history row.
//
// A transition log the application can rewrite is not a log (migration 0011:
// no DELETE grant on finding_history), so this only ever inserts. changed_by is
// nil for a transition the engine made rather than an operator.
func (Findings) RecordTransition(ctx context.Context, c *Conn, findingID uuid.UUID, from, to, reason string, at time.Time) error {
	const q = `
		INSERT INTO finding_history (tenant_id, finding_id, from_status, to_status, reason, changed_at)
		VALUES ($1, $2, nullif($3,'')::finding_status, $4::finding_status, $5, $6)`
	_, err := c.Exec(ctx, q, c.Tenant().UUID(), findingID, from, to, reason, at)
	return mapError(err)
}

// OpenForAssetLocators returns the open findings on an asset whose endpoint is
// in the given locator set, for the lifecycle: a finding on a re-observed
// endpoint that did not fire this pass has been remediated.
func (Findings) OpenForAssetLocators(ctx context.Context, c *Conn, assetID uuid.UUID, locators []string) ([]OpenFinding, error) {
	if len(locators) == 0 {
		return nil, nil
	}
	const q = `
		SELECT finding_id, dedup_key, coalesce(instance_locator,''), status
		  FROM findings
		 WHERE tenant_id = $1 AND asset_id = $2
		   AND status IN ('open', 'confirmed')
		   AND instance_locator = ANY($3)`
	rows, err := c.Query(ctx, q, c.Tenant().UUID(), assetID, locators)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []OpenFinding
	for rows.Next() {
		var f OpenFinding
		if err := rows.Scan(&f.ID, &f.DedupKey, &f.Locator, &f.Status); err != nil {
			return nil, mapError(err)
		}
		out = append(out, f)
	}
	return out, mapError(rows.Err())
}

// OpenFinding is the lifecycle's view of an existing finding.
type OpenFinding struct {
	ID       uuid.UUID
	DedupKey string
	Locator  string
	Status   string
}

// MarkRemediated moves a finding to remediated. Used by the lifecycle when the
// endpoint was re-observed and the rule did not fire — the issue is gone, and
// that is different from the endpoint simply not being scanned.
func (Findings) MarkRemediated(ctx context.Context, c *Conn, findingID uuid.UUID, at time.Time) error {
	const q = `
		UPDATE findings
		   SET status = 'remediated', resolved_at = $3, last_seen = $3
		 WHERE tenant_id = $1 AND finding_id = $2 AND status IN ('open', 'confirmed')`
	_, err := c.Exec(ctx, q, c.Tenant().UUID(), findingID, at)
	return mapError(err)
}

// ============================================================================
// Read path (session 18). The pipeline above WRITES findings; the operator API
// READS them back — the first time the dedup key, the exposure rows and the
// evidence link are read through anything but a test.
// ============================================================================

// FindingSummary is one row of the finding list. RuleName and the asset hostname
// are joined in so the list is legible without a second call per row; the
// exposure count is here because "seen from N zones" is the number the backlog
// is read by, and it is count(DISTINCT zone), not a row count (ADR-008/010).
type FindingSummary struct {
	ID            uuid.UUID
	RuleName      string
	Category      string
	Severity      string
	Status        string
	AssetID       uuid.UUID
	AssetHostname string
	Locator       string
	Confidence    float64
	ExposureZones int
	FirstSeen     time.Time
	LastSeen      time.Time

	// Priority signals (P3.4, ADR-069). KEV/EPSS/CVSS are nullable-shaped: KEV is a
	// membership bool (false = unlisted, never "unexploited"); EPSS and CVSS are
	// pointers (nil = unscored/unknown, never 0). PriorityScore is the bit-packed
	// lexicographic order (KEV > exposure > criticality > EPSS/CVSS > severity);
	// PriorityBasis names the dominant reason for a legible order.
	KEV            bool
	KEVRansomware  bool
	KEVDateAdded   *time.Time
	EPSS           *float64
	EPSSPercentile *float64
	CVSS           *float64
	PriorityScore  int64
	PriorityBasis  string
}

// FindingListFilter narrows the list. Empty fields do not filter.
type FindingListFilter struct {
	Status   string // finding_status, or "" for any
	Severity string // severity, or "" for any
	AssetID  uuid.UUID
	RuleID   uuid.UUID
}

// FindingPage is a keyset page of the finding list, ordered by priority
// (ADR-069). The cursor is (priority_score, finding_id), not a timestamp, because
// the list is priority-ordered — the first meaningful order it has had.
type FindingPage struct {
	Findings  []FindingSummary
	NextScore int64
	NextID    uuid.UUID
	HasNext   bool
}

// EvidenceRead is one evidence record as an analyst reads it back.
//
// ObservationID is a POINTER because the column is nullable and EXPECTED to go
// null when the observation partition drops (ADR-016). The write-path type
// FindingEvidence.ObservationID is a bare uuid — fine for writing, where a real
// observation always exists, but a read that reused it would fail to scan the
// null, or worse, coalesce it to the zero uuid and show a broken link as a real
// one. nil here means "the observation that proved this has aged out", which the
// API must state honestly rather than hide.
type EvidenceRead struct {
	ObservationID  *uuid.UUID
	Type           string
	Data           map[string]any
	CapturedAt     time.Time
	HasObjectStore bool // the summary is not the whole of it (ADR-015)
}

// ExposureRead is one vantage point a finding is visible from. LastConfirmed is
// carried because exposure is derived and goes stale after a network change, and
// the schema (finding_exposure.last_confirmed) exists to make that visible
// rather than silent — so the read surfaces it.
type ExposureRead struct {
	ZoneID            uuid.UUID
	ZoneName          string
	ZoneType          string
	InternetReachable bool
	AuthRequired      bool
	LastConfirmed     time.Time
}

// FindingDetail is the finding-verification view: everything an analyst needs to
// confirm the claim by hand without re-scanning.
type FindingDetail struct {
	ID          uuid.UUID
	AssetID     uuid.UUID
	AssetHost   string
	RuleName    string
	Category    string
	CWE         string
	Remediation string
	Source      string
	DedupKey    string
	Locator     string
	Severity    string
	Confidence  float64
	Status      string
	HasVulnDef  bool // vuln_def_id present; nothing branches on it (ADR-009)
	FirstSeen   time.Time
	LastSeen    time.Time
	ResolvedAt  *time.Time
	Evidence    []EvidenceRead
	Exposures   []ExposureRead

	// Priority signals (P3.4, ADR-069), so the detail view shows WHY a finding
	// ranks where the list put it. Same nullable shapes as FindingSummary: KEV is
	// membership (false = unlisted); EPSS/CVSS are pointers (nil = unscored/unknown,
	// never 0). No priority_score here — a single finding has no ordering to encode.
	KEV            bool
	KEVRansomware  bool
	KEVDateAdded   *time.Time
	EPSS           *float64
	EPSSPercentile *float64
	CVSS           *float64
	PriorityBasis  string
}

// List returns a keyset page of findings ordered by priority, highest first
// (ADR-069) — the finding list's first meaningful order. The cursor is
// (priority_score, finding_id), not a timestamp, so a row cannot shift under a
// paging client. Rule name and asset hostname are joined; the exposure count is
// DISTINCT zones per finding, never a join-row count — one finding seen from
// three zones is one finding (ADR-010). KEV/EPSS/CVSS are LEFT-joined off the
// finding's optional vuln_def_id: a finding with no CVE, or a CVE unlisted in KEV
// and unscored by EPSS, simply has no such row — absence, not a low value.
func (Findings) List(ctx context.Context, c *Conn, f FindingListFilter, beforeScore int64, beforeID uuid.UUID, limit int) (*FindingPage, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	var assetArg, ruleArg any
	if f.AssetID != uuid.Nil {
		assetArg = f.AssetID
	}
	if f.RuleID != uuid.Nil {
		ruleArg = f.RuleID
	}
	var statusArg, sevArg any
	if f.Status != "" {
		statusArg = f.Status
	}
	if f.Severity != "" {
		sevArg = f.Severity
	}
	// The cursor is present iff beforeID is set (score alone can be 0 legitimately).
	var cursorScore any
	var cursorID any
	if beforeID != uuid.Nil {
		cursorScore, cursorID = beforeScore, beforeID
	}

	// Priority (ADR-069), computed here, ordered here. The bit-packing weights KEV
	// above the sum of every lower term (1e9 vs a max ~1.5e8), so a KEV finding
	// outranks any non-KEV one regardless of CVSS — the inversion, structural not
	// tuned. risk = COALESCE(epss, cvss/10): an unscored-EPSS finding is ranked by
	// the CVSS we know, NOT dropped to zero (absence is not a low value, ADR-069);
	// only a finding with neither falls to 0 there and is flagged 'unscored'.
	const q = `
		SELECT * FROM (
		  SELECT f.finding_id, r.name, r.category, f.severity::text, f.status::text,
		         f.asset_id, coalesce(a.primary_hostname, ''), coalesce(f.instance_locator, ''),
		         f.confidence,
		         (SELECT count(DISTINCT fe.zone_id) FROM finding_exposure fe
		           WHERE fe.tenant_id = f.tenant_id AND fe.finding_id = f.finding_id) AS exposure_zones,
		         f.first_seen, f.last_seen,
		         (k.cve_id IS NOT NULL) AS kev,
		         coalesce(k.known_ransomware, false) AS kev_ransomware,
		         k.date_added AS kev_date_added,
		         e.score AS epss, e.percentile AS epss_pct, vd.cvss_base AS cvss,
		         ( (CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END)::bigint * 1000000000
		         + (CASE WHEN EXISTS (SELECT 1 FROM finding_exposure fx
		                               WHERE fx.tenant_id = f.tenant_id AND fx.finding_id = f.finding_id
		                                 AND fx.internet_reachable) THEN 1 ELSE 0 END)::bigint * 100000000
		         + (CASE a.criticality WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END)::bigint * 10000000
		         + coalesce(round(coalesce(e.score, vd.cvss_base/10.0) * 1000), 0)::bigint * 1000
		         + (CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END)::bigint
		         ) AS priority_score,
		         CASE
		           WHEN k.cve_id IS NOT NULL THEN 'KEV-listed'
		           WHEN e.score IS NOT NULL THEN 'EPSS ' || to_char(e.score, 'FM0.00000')
		           WHEN vd.cvss_base IS NOT NULL THEN 'CVSS ' || vd.cvss_base::text
		           ELSE 'unscored'
		         END AS priority_basis
		    FROM findings f
		    JOIN rules r  ON r.rule_id = f.rule_id
		    JOIN assets a ON a.tenant_id = f.tenant_id AND a.asset_id = f.asset_id
		    LEFT JOIN vulnerability_defs vd ON vd.vuln_def_id = f.vuln_def_id
		    LEFT JOIN kev  k ON k.cve_id = vd.cve_id
		    LEFT JOIN epss e ON e.cve_id = vd.cve_id
		   WHERE f.tenant_id = $1
		     AND ($4::finding_status IS NULL OR f.status = $4::finding_status)
		     AND ($5::severity IS NULL OR f.severity = $5::severity)
		     AND ($6::uuid IS NULL OR f.asset_id = $6)
		     AND ($7::uuid IS NULL OR f.rule_id = $7)
		) s
		 WHERE ($2::bigint IS NULL OR (s.priority_score, s.finding_id) < ($2, $3))
		 ORDER BY s.priority_score DESC, s.finding_id DESC
		 LIMIT $8`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), cursorScore, cursorID,
		statusArg, sevArg, assetArg, ruleArg, limit)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	page := &FindingPage{}
	for rows.Next() {
		var s FindingSummary
		if err := rows.Scan(&s.ID, &s.RuleName, &s.Category, &s.Severity, &s.Status,
			&s.AssetID, &s.AssetHostname, &s.Locator, &s.Confidence, &s.ExposureZones,
			&s.FirstSeen, &s.LastSeen,
			&s.KEV, &s.KEVRansomware, &s.KEVDateAdded, &s.EPSS, &s.EPSSPercentile, &s.CVSS,
			&s.PriorityScore, &s.PriorityBasis); err != nil {
			return nil, mapError(err)
		}
		page.Findings = append(page.Findings, s)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(err)
	}
	if len(page.Findings) == limit {
		last := page.Findings[len(page.Findings)-1]
		page.NextScore, page.NextID, page.HasNext = last.PriorityScore, last.ID, true
	}
	return page, nil
}

// GetFinding returns the full detail for one finding, or ErrNotFound (which,
// under RLS, is also what a cross-tenant id gives — the two are indistinguishable
// on purpose). Evidence and exposures are separate reads because they are
// one-to-many; each is empty rather than an error when there is none.
func (Findings) GetFinding(ctx context.Context, c *Conn, id uuid.UUID) (*FindingDetail, error) {
	// Priority signals off the optional vuln_def_id (ADR-069). LEFT JOINs, so a
	// finding with no CVE — or a CVE unlisted in KEV and unscored by EPSS — simply
	// carries nulls: absence, not a low value. priority_basis matches List's CASE.
	const q = `
		SELECT f.finding_id, f.asset_id, coalesce(a.primary_hostname, ''),
		       r.name, r.category, coalesce(r.cwe, ''), coalesce(r.remediation_template, ''),
		       f.source::text, f.dedup_key, coalesce(f.instance_locator, ''),
		       f.severity::text, f.confidence, f.status::text,
		       (f.vuln_def_id IS NOT NULL),
		       f.first_seen, f.last_seen, f.resolved_at,
		       (k.cve_id IS NOT NULL) AS kev,
		       coalesce(k.known_ransomware, false) AS kev_ransomware,
		       k.date_added AS kev_date_added,
		       e.score AS epss, e.percentile AS epss_pct, vd.cvss_base AS cvss,
		       CASE
		         WHEN k.cve_id IS NOT NULL THEN 'KEV-listed'
		         WHEN e.score IS NOT NULL THEN 'EPSS ' || to_char(e.score, 'FM0.00000')
		         WHEN vd.cvss_base IS NOT NULL THEN 'CVSS ' || vd.cvss_base::text
		         ELSE 'unscored'
		       END AS priority_basis
		  FROM findings f
		  JOIN rules r  ON r.rule_id = f.rule_id
		  JOIN assets a ON a.tenant_id = f.tenant_id AND a.asset_id = f.asset_id
		  LEFT JOIN vulnerability_defs vd ON vd.vuln_def_id = f.vuln_def_id
		  LEFT JOIN kev  k ON k.cve_id = vd.cve_id
		  LEFT JOIN epss e ON e.cve_id = vd.cve_id
		 WHERE f.tenant_id = $1 AND f.finding_id = $2`

	var d FindingDetail
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), id).Scan(
		&d.ID, &d.AssetID, &d.AssetHost, &d.RuleName, &d.Category, &d.CWE, &d.Remediation,
		&d.Source, &d.DedupKey, &d.Locator, &d.Severity, &d.Confidence, &d.Status,
		&d.HasVulnDef, &d.FirstSeen, &d.LastSeen, &d.ResolvedAt,
		&d.KEV, &d.KEVRansomware, &d.KEVDateAdded, &d.EPSS, &d.EPSSPercentile, &d.CVSS,
		&d.PriorityBasis)
	if err != nil {
		return nil, mapError(err)
	}

	ev, err := findingEvidence(ctx, c, id)
	if err != nil {
		return nil, err
	}
	d.Evidence = ev

	ex, err := findingExposures(ctx, c, id)
	if err != nil {
		return nil, err
	}
	d.Exposures = ex
	return &d, nil
}

func findingEvidence(ctx context.Context, c *Conn, findingID uuid.UUID) ([]EvidenceRead, error) {
	const q = `
		SELECT observation_id, evidence_type::text, data, captured_at,
		       (object_store_ref IS NOT NULL)
		  FROM evidence
		 WHERE tenant_id = $1 AND finding_id = $2
		 ORDER BY captured_at`
	rows, err := c.Query(ctx, q, c.Tenant().UUID(), findingID)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []EvidenceRead
	for rows.Next() {
		var (
			e   EvidenceRead
			raw []byte
		)
		// observation_id scans into *uuid.UUID: nil when the observation has aged
		// out (ADR-016). See EvidenceRead.
		if err := rows.Scan(&e.ObservationID, &e.Type, &raw, &e.CapturedAt, &e.HasObjectStore); err != nil {
			return nil, mapError(err)
		}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &e.Data); err != nil {
				return nil, mapError(err)
			}
		}
		out = append(out, e)
	}
	return out, mapError(rows.Err())
}

func findingExposures(ctx context.Context, c *Conn, findingID uuid.UUID) ([]ExposureRead, error) {
	const q = `
		SELECT fe.zone_id, coalesce(z.name, ''), z.zone_type::text,
		       fe.internet_reachable, fe.auth_required, fe.last_confirmed
		  FROM finding_exposure fe
		  JOIN scan_zones z ON z.tenant_id = fe.tenant_id AND z.zone_id = fe.zone_id
		 WHERE fe.tenant_id = $1 AND fe.finding_id = $2
		 ORDER BY fe.internet_reachable DESC, z.name`
	rows, err := c.Query(ctx, q, c.Tenant().UUID(), findingID)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []ExposureRead
	for rows.Next() {
		var e ExposureRead
		if err := rows.Scan(&e.ZoneID, &e.ZoneName, &e.ZoneType,
			&e.InternetReachable, &e.AuthRequired, &e.LastConfirmed); err != nil {
			return nil, mapError(err)
		}
		out = append(out, e)
	}
	return out, mapError(rows.Err())
}

// ZoneExposure is the exposure-by-zone summary for one zone: how many OPEN
// findings are visible from it, by severity.
//
// Findings is count(DISTINCT finding_id), never a count of finding_exposure
// rows: a single finding visible from three zones must count once in each zone's
// column, not inflate a total. There is deliberately no grand total here — a
// caller summing these columns would double-count the cross-zone findings, which
// is the number an executive reads first (ADR-008, ADR-010).
type ZoneExposure struct {
	ZoneID   uuid.UUID
	ZoneName string
	ZoneType string
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
	Total    int // distinct open findings visible from THIS zone (not summable across zones)
}

// ExposureByZone returns one row per zone that has at least one open finding
// exposed from it, worst-exposed first.
func (Findings) ExposureByZone(ctx context.Context, c *Conn) ([]ZoneExposure, error) {
	// count(DISTINCT ...) FILTER per severity: finding_exposure is unique per
	// (finding, zone), so within a zone a finding appears once — but the DISTINCT
	// is kept anyway so the query stays correct if that constraint ever changes,
	// and to make the intent unmissable to the next reader (note 4).
	const q = `
		SELECT z.zone_id, coalesce(z.name, ''), z.zone_type::text,
		       count(DISTINCT f.finding_id) FILTER (WHERE f.severity = 'critical'),
		       count(DISTINCT f.finding_id) FILTER (WHERE f.severity = 'high'),
		       count(DISTINCT f.finding_id) FILTER (WHERE f.severity = 'medium'),
		       count(DISTINCT f.finding_id) FILTER (WHERE f.severity = 'low'),
		       count(DISTINCT f.finding_id) FILTER (WHERE f.severity = 'info'),
		       count(DISTINCT f.finding_id)
		  FROM finding_exposure fe
		  JOIN findings f  ON f.tenant_id = fe.tenant_id AND f.finding_id = fe.finding_id
		  JOIN scan_zones z ON z.tenant_id = fe.tenant_id AND z.zone_id = fe.zone_id
		 WHERE fe.tenant_id = $1 AND f.status IN ('open', 'confirmed')
		 GROUP BY z.zone_id, z.name, z.zone_type
		 ORDER BY count(DISTINCT f.finding_id) FILTER (WHERE f.severity = 'critical') DESC,
		          count(DISTINCT f.finding_id) DESC`
	rows, err := c.Query(ctx, q, c.Tenant().UUID())
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []ZoneExposure
	for rows.Next() {
		var z ZoneExposure
		if err := rows.Scan(&z.ZoneID, &z.ZoneName, &z.ZoneType,
			&z.Critical, &z.High, &z.Medium, &z.Low, &z.Info, &z.Total); err != nil {
			return nil, mapError(err)
		}
		out = append(out, z)
	}
	return out, mapError(rows.Err())
}

// ExportRowCap bounds a CSV export. An export is the read most likely to be
// pointed at a whole tenant's findings, and the failure that matters is an
// incomplete file that looks complete. So this is not a silent truncation
// point: the API asks for ExportRowCap+1 rows and REFUSES the export when more
// exist, telling the caller to narrow the filter, rather than returning a
// capped file (note: session 18). High enough that a real export passes.
const ExportRowCap = 50000

// ListForExport returns up to `max` findings matching the filter, newest first,
// with no cursor — the whole set in one shot, for CSV. Callers pass
// ExportRowCap+1 and refuse when the result exceeds the cap. `max` is itself
// hard-bounded so a caller cannot ask the database for an unbounded scan.
func (Findings) ListForExport(ctx context.Context, c *Conn, f FindingListFilter, max int) ([]FindingSummary, error) {
	if max <= 0 || max > ExportRowCap+1 {
		max = ExportRowCap + 1
	}
	var assetArg, ruleArg, statusArg, sevArg any
	if f.AssetID != uuid.Nil {
		assetArg = f.AssetID
	}
	if f.RuleID != uuid.Nil {
		ruleArg = f.RuleID
	}
	if f.Status != "" {
		statusArg = f.Status
	}
	if f.Severity != "" {
		sevArg = f.Severity
	}

	const q = `
		SELECT f.finding_id, r.name, r.category, f.severity::text, f.status::text,
		       f.asset_id, coalesce(a.primary_hostname, ''), coalesce(f.instance_locator, ''),
		       f.confidence,
		       (SELECT count(DISTINCT fe.zone_id) FROM finding_exposure fe
		         WHERE fe.tenant_id = f.tenant_id AND fe.finding_id = f.finding_id),
		       f.first_seen, f.last_seen
		  FROM findings f
		  JOIN rules r  ON r.rule_id = f.rule_id
		  JOIN assets a ON a.tenant_id = f.tenant_id AND a.asset_id = f.asset_id
		 WHERE f.tenant_id = $1
		   AND ($2::finding_status IS NULL OR f.status = $2::finding_status)
		   AND ($3::severity IS NULL OR f.severity = $3::severity)
		   AND ($4::uuid IS NULL OR f.asset_id = $4)
		   AND ($5::uuid IS NULL OR f.rule_id = $5)
		 ORDER BY f.last_seen DESC, f.finding_id DESC
		 LIMIT $6`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), statusArg, sevArg, assetArg, ruleArg, max)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []FindingSummary
	for rows.Next() {
		var s FindingSummary
		if err := rows.Scan(&s.ID, &s.RuleName, &s.Category, &s.Severity, &s.Status,
			&s.AssetID, &s.AssetHostname, &s.Locator, &s.Confidence, &s.ExposureZones,
			&s.FirstSeen, &s.LastSeen); err != nil {
			return nil, mapError(err)
		}
		out = append(out, s)
	}
	return out, mapError(rows.Err())
}
