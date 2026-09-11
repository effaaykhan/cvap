package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// The console's landing and health reads (design spec backlog #12, rungs 2, 4
// and 5). Each number here is computed in SQL from the same rows the list
// endpoints page over, so it is reproducible from those lists — a count is a
// count of findings the operator can open, never a rollup with its own life.

// FindingStats is the summary the operator landing draws from: exact counts of
// what is open now, what changed inside a window, and a daily series.
type FindingStats struct {
	// Open is findings in open or confirmed status. KEVOpen is the subset whose
	// CVE is in CISA KEV. BySeverity counts the open set per severity word.
	Open       int
	KEVOpen    int
	BySeverity map[string]int

	// Changed inside [Since, now).
	Since          time.Time
	NewSince       int // first_seen inside the window, still open
	ResolvedSince  int // resolved_at inside the window
	ReopenedSince  int // a recorded transition back to open inside the window
	KEVListedSince int // open findings whose CVE was added to KEV inside the window

	// The worst of what is new and what re-ranked, for the landing's change list.
	NewItems       []ChangedFinding
	KEVListedItems []ChangedFinding

	// WorstAssets are the systems carrying the most open findings, worst first
	// — the answer to "which system is vulnerable", by asset rather than by rule.
	WorstAssets []AssetRisk

	// Trend is one point per day, oldest first. Open at day D counts findings
	// first seen on or before D and not resolved by the end of D; KEV is the
	// subset in KEV today. Derived from first_seen and resolved_at, which is
	// what the finding rows carry — no separate rollup to drift.
	Trend []TrendPoint
}

// ChangedFinding is one finding named on the change list.
type ChangedFinding struct {
	ID            uuid.UUID
	RuleName      string
	AssetHostname string
	Severity      string
	KEV           bool
	At            time.Time // first_seen, or the KEV listing date
}

// AssetRisk is one system's open-finding burden.
type AssetRisk struct {
	ID            uuid.UUID
	Hostname      string
	Address       string
	Open          int
	Critical      int
	High          int
	Medium        int
	Low           int
	KEV           int
	WorstSeverity string
}

// TrendPoint is one day of the series.
type TrendPoint struct {
	Day  time.Time
	Open int
	KEV  int
}

const changedItemsLimit = 8

// Stats computes the landing summary. since bounds the change window; days
// bounds the trend series (each day ending at midnight UTC, the last being
// today so far).
func (Findings) Stats(ctx context.Context, c *Conn, since, now time.Time, days int) (*FindingStats, error) {
	if days < 1 || days > 90 {
		days = 30
	}
	tid := c.Tenant().UUID()
	out := &FindingStats{Since: since, BySeverity: map[string]int{}}

	// One pass for the counts: every predicate reads the same joined row the
	// list endpoint reads, so a number here is a number the list can reproduce.
	const counts = `
		SELECT
		  count(*) FILTER (WHERE f.status IN ('open','confirmed')),
		  count(*) FILTER (WHERE f.status IN ('open','confirmed') AND k.cve_id IS NOT NULL),
		  count(*) FILTER (WHERE f.status IN ('open','confirmed') AND f.first_seen >= $2),
		  count(*) FILTER (WHERE f.resolved_at IS NOT NULL AND f.resolved_at >= $2),
		  count(*) FILTER (WHERE f.status IN ('open','confirmed') AND k.date_added IS NOT NULL AND k.date_added >= $2::date)
		  FROM findings f
		  LEFT JOIN vulnerability_defs vd ON vd.vuln_def_id = f.vuln_def_id
		  LEFT JOIN kev k ON k.cve_id = vd.cve_id
		 WHERE f.tenant_id = $1`
	if err := c.QueryRow(ctx, counts, tid, since).Scan(
		&out.Open, &out.KEVOpen, &out.NewSince, &out.ResolvedSince, &out.KEVListedSince); err != nil {
		return nil, mapError(err)
	}

	const bySev = `
		SELECT severity::text, count(*) FROM findings
		 WHERE tenant_id = $1 AND status IN ('open','confirmed')
		 GROUP BY severity`
	rows, err := c.Query(ctx, bySev, tid)
	if err != nil {
		return nil, mapError(err)
	}
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			rows.Close()
			return nil, mapError(err)
		}
		out.BySeverity[sev] = n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, mapError(err)
	}

	// Reopened: the transition table is the record (Findings.RecordTransition),
	// so this counts transitions rather than inferring from timestamps.
	const reopened = `
		SELECT count(*) FROM finding_history
		 WHERE tenant_id = $1 AND to_status = 'open' AND from_status IS NOT NULL
		   AND from_status <> 'open' AND changed_at >= $2`
	if err := c.QueryRow(ctx, reopened, tid, since).Scan(&out.ReopenedSince); err != nil {
		return nil, mapError(err)
	}

	items := func(where, order string, at string) ([]ChangedFinding, error) {
		q := `
		SELECT f.finding_id, r.name, coalesce(a.primary_hostname, ''), f.severity::text,
		       (k.cve_id IS NOT NULL), ` + at + `
		  FROM findings f
		  JOIN rules r ON r.rule_id = f.rule_id
		  JOIN assets a ON a.tenant_id = f.tenant_id AND a.asset_id = f.asset_id
		  LEFT JOIN vulnerability_defs vd ON vd.vuln_def_id = f.vuln_def_id
		  LEFT JOIN kev k ON k.cve_id = vd.cve_id
		 WHERE f.tenant_id = $1 AND f.status IN ('open','confirmed') AND ` + where + `
		 ORDER BY ` + order + `
		 LIMIT $3`
		rows, err := c.Query(ctx, q, tid, since, changedItemsLimit)
		if err != nil {
			return nil, mapError(err)
		}
		defer rows.Close()
		var list []ChangedFinding
		for rows.Next() {
			var i ChangedFinding
			if err := rows.Scan(&i.ID, &i.RuleName, &i.AssetHostname, &i.Severity, &i.KEV, &i.At); err != nil {
				return nil, mapError(err)
			}
			list = append(list, i)
		}
		return list, mapError(rows.Err())
	}
	// Newest first, KEV ahead, then the severity word's rank — the same order a
	// reader would triage them in.
	if out.NewItems, err = items(`f.first_seen >= $2`,
		`(k.cve_id IS NOT NULL) DESC, f.severity DESC, f.first_seen DESC`, `f.first_seen`); err != nil {
		return nil, err
	}
	if out.KEVListedItems, err = items(`k.date_added IS NOT NULL AND k.date_added >= $2::date`,
		`k.date_added DESC, f.severity DESC`, `k.date_added::timestamptz`); err != nil {
		return nil, err
	}

	// The systems, worst first: KEV first, then severity weight, then count.
	const worstAssets = `
		SELECT a.asset_id, coalesce(a.primary_hostname, ''),
		       coalesce((SELECT host(ad.ip_address) FROM asset_addresses ad
		                  WHERE ad.tenant_id = a.tenant_id AND ad.asset_id = a.asset_id AND ad.valid_to IS NULL
		                  ORDER BY ad.valid_from LIMIT 1), ''),
		       count(*),
		       count(*) FILTER (WHERE f.severity = 'critical'),
		       count(*) FILTER (WHERE f.severity = 'high'),
		       count(*) FILTER (WHERE f.severity = 'medium'),
		       count(*) FILTER (WHERE f.severity = 'low'),
		       count(*) FILTER (WHERE k.cve_id IS NOT NULL),
		       max(CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END)
		  FROM findings f
		  JOIN assets a ON a.tenant_id = f.tenant_id AND a.asset_id = f.asset_id
		  LEFT JOIN vulnerability_defs vd ON vd.vuln_def_id = f.vuln_def_id
		  LEFT JOIN kev k ON k.cve_id = vd.cve_id
		 WHERE f.tenant_id = $1 AND f.status IN ('open','confirmed')
		 GROUP BY a.asset_id, a.primary_hostname, a.tenant_id
		 ORDER BY count(*) FILTER (WHERE k.cve_id IS NOT NULL) DESC,
		          max(CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) DESC,
		          count(*) DESC
		 LIMIT 8`
	arows, err := c.Query(ctx, worstAssets, tid)
	if err != nil {
		return nil, mapError(err)
	}
	for arows.Next() {
		var a AssetRisk
		var worst int
		if err := arows.Scan(&a.ID, &a.Hostname, &a.Address, &a.Open, &a.Critical, &a.High, &a.Medium, &a.Low, &a.KEV, &worst); err != nil {
			arows.Close()
			return nil, mapError(err)
		}
		a.WorstSeverity = severityWord(worst)
		out.WorstAssets = append(out.WorstAssets, a)
	}
	arows.Close()
	if err := arows.Err(); err != nil {
		return nil, mapError(err)
	}

	// The series. Day boundaries are UTC midnights; the last point is today,
	// counted as of now.
	const trend = `
		WITH days AS (
		  SELECT (date_trunc('day', $3::timestamptz) - (n || ' days')::interval) AS day
		    FROM generate_series($2::int - 1, 0, -1) AS n
		)
		SELECT d.day,
		       (SELECT count(*) FROM findings f
		         WHERE f.tenant_id = $1
		           AND f.first_seen < d.day + interval '1 day'
		           AND (f.resolved_at IS NULL OR f.resolved_at >= d.day + interval '1 day')),
		       (SELECT count(*) FROM findings f
		          JOIN vulnerability_defs vd ON vd.vuln_def_id = f.vuln_def_id
		          JOIN kev k ON k.cve_id = vd.cve_id
		         WHERE f.tenant_id = $1
		           AND f.first_seen < d.day + interval '1 day'
		           AND (f.resolved_at IS NULL OR f.resolved_at >= d.day + interval '1 day'))
		  FROM days d
		 ORDER BY d.day`
	trows, err := c.Query(ctx, trend, tid, days, now)
	if err != nil {
		return nil, mapError(err)
	}
	defer trows.Close()
	for trows.Next() {
		var p TrendPoint
		if err := trows.Scan(&p.Day, &p.Open, &p.KEV); err != nil {
			return nil, mapError(err)
		}
		out.Trend = append(out.Trend, p)
	}
	return out, mapError(trows.Err())
}

// CountUnresolved counts accepted observations correlation has not attached to
// an asset, inside a window (observations is partitioned by observed_at).
func (Observations) CountUnresolved(ctx context.Context, c *Conn, since, until time.Time) (int64, error) {
	const q = `
		SELECT count(*) FROM observations
		 WHERE tenant_id = $1 AND observed_at >= $2 AND observed_at < $3
		   AND asset_id IS NULL AND ingest_state = 'accepted'`
	var n int64
	if err := c.QueryRow(ctx, q, c.Tenant().UUID(), since, until).Scan(&n); err != nil {
		return 0, mapError(err)
	}
	return n, nil
}

// Active lists the kill switches not yet resolved, newest first.
func (KillSwitches) Active(ctx context.Context, c *Conn) ([]KillSwitch, error) {
	const q = `
		SELECT kill_id, scope, scope_zone_id, scope_scan_id, issued_by, issued_at, reason, resolved_at
		  FROM kill_switches
		 WHERE tenant_id = $1 AND resolved_at IS NULL
		 ORDER BY issued_at DESC`
	rows, err := c.Query(ctx, q, c.Tenant().UUID())
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	var out []KillSwitch
	for rows.Next() {
		var k KillSwitch
		if err := rows.Scan(&k.ID, &k.Scope, &k.ZoneID, &k.ScanID, &k.IssuedBy,
			&k.IssuedAt, &k.Reason, &k.ResolvedAt); err != nil {
			return nil, mapError(err)
		}
		out = append(out, k)
	}
	return out, mapError(rows.Err())
}

// ActiveWithQueuedJobs lists scans that are still meant to run and hold at
// least one queued job — the population a blocked-for-capacity check walks.
// Whether a queued job CAN be claimed is CountDispatchable's question, asked per
// scan by the caller, with the same predicate Claim uses.
func (Scans) ActiveWithQueuedJobs(ctx context.Context, c *Conn) ([]Scan, error) {
	const q = `
		SELECT s.scan_id, s.policy_id, s.requested_by, s.scan_type, s.status, s.safety_mode,
		       s.created_at, s.started_at, s.completed_at
		  FROM scans s
		 WHERE s.tenant_id = $1
		   AND s.status IN ('pending','planning','running')
		   AND EXISTS (SELECT 1 FROM scan_jobs j
		                WHERE j.tenant_id = s.tenant_id AND j.scan_id = s.scan_id AND j.status = 'queued')
		 ORDER BY s.created_at DESC
		 LIMIT 200`
	rows, err := c.Query(ctx, q, c.Tenant().UUID())
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	var out []Scan
	for rows.Next() {
		var s Scan
		if err := rows.Scan(&s.ID, &s.PolicyID, &s.RequestedBy, &s.ScanType, &s.Status,
			&s.SafetyMode, &s.CreatedAt, &s.StartedAt, &s.CompletedAt); err != nil {
			return nil, mapError(err)
		}
		out = append(out, s)
	}
	return out, mapError(rows.Err())
}

func severityWord(rank int) string {
	switch rank {
	case 4:
		return "critical"
	case 3:
		return "high"
	case 2:
		return "medium"
	case 1:
		return "low"
	default:
		return "info"
	}
}
