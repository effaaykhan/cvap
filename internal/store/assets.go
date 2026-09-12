package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type Criticality string

const (
	CriticalityUnknown  Criticality = "unknown"
	CriticalityLow      Criticality = "low"
	CriticalityMedium   Criticality = "medium"
	CriticalityHigh     Criticality = "high"
	CriticalityCritical Criticality = "critical"
)

// Asset is derived by Core from observations (ADR-006). Nothing in this package
// derives anything — these are persistence methods for the derivation stage in
// internal/control to call.
//
// There is no Zone field, and adding one is a blocker (ADR-008). Assets move;
// a stored zone is wrong shortly after it is written, and wrong in the specific
// way that corrupts exposure reporting. Zone belongs to the observation, and
// exposure is derived from which vantage points saw what.
//
// There is likewise no current-IP field. An IP is a time-bounded relationship,
// held in asset_addresses with valid_from / valid_to.
type Asset struct {
	ID          uuid.UUID
	Hostname    string
	OSFamily    string
	OSVersion   string
	DeviceType  string
	Vendor      string
	Criticality Criticality
	Environment string
	Owner       string

	// Fragile caps scan rate and suppresses aggressive checks regardless of
	// what the policy permits (ADR-024). It travels to the scan point per Task,
	// because it is a Core-held attribute the scan point cannot derive.
	Fragile bool

	FirstSeen time.Time
	LastSeen  time.Time

	// Risk facts, filled by List only (Create and Get do not carry them): the
	// answer to "which system is vulnerable" on the inventory row itself, so an
	// operator does not open 274 details to find the five that matter.
	Address            string // the earliest current address, "" when none
	OpenFindings       int
	WorstSeverity      string // critical|high|medium|low|info, "" when none open
	KEVFindings        int
	ReleaseResolved    bool // inputs to domain.AssetAdvisoryStatus (ADR-068)
	InCoverage         bool
	HasAdvisoryFinding bool
}

type Assets struct{}

func (Assets) Create(ctx context.Context, c *Conn, a Asset) (*Asset, error) {
	const q = `
		INSERT INTO assets (tenant_id, primary_hostname, os_family, os_version,
		                    device_type, vendor, criticality, environment, owner, fragile)
		VALUES ($1, nullif($2,''), nullif($3,''), nullif($4,''), nullif($5,''),
		        nullif($6,''), coalesce(nullif($7,'')::asset_criticality, 'unknown'),
		        nullif($8,''), nullif($9,''), $10)
		RETURNING asset_id, coalesce(primary_hostname,''), coalesce(os_family,''),
		          coalesce(os_version,''), coalesce(device_type,''), coalesce(vendor,''),
		          criticality, coalesce(environment,''), coalesce(owner,''), fragile,
		          first_seen, last_seen`

	var out Asset
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), a.Hostname, a.OSFamily, a.OSVersion,
		a.DeviceType, a.Vendor, string(a.Criticality), a.Environment, a.Owner, a.Fragile).
		Scan(&out.ID, &out.Hostname, &out.OSFamily, &out.OSVersion, &out.DeviceType,
			&out.Vendor, &out.Criticality, &out.Environment, &out.Owner, &out.Fragile,
			&out.FirstSeen, &out.LastSeen)
	if err != nil {
		return nil, mapError(err)
	}
	return &out, nil
}

func (Assets) GetByID(ctx context.Context, c *Conn, id uuid.UUID) (*Asset, error) {
	const q = `
		SELECT asset_id, coalesce(primary_hostname,''), coalesce(os_family,''),
		       coalesce(os_version,''), coalesce(device_type,''), coalesce(vendor,''),
		       criticality, coalesce(environment,''), coalesce(owner,''), fragile,
		       first_seen, last_seen
		  FROM assets
		 WHERE tenant_id = $1 AND asset_id = $2`

	var a Asset
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), id).
		Scan(&a.ID, &a.Hostname, &a.OSFamily, &a.OSVersion, &a.DeviceType, &a.Vendor,
			&a.Criticality, &a.Environment, &a.Owner, &a.Fragile, &a.FirstSeen, &a.LastSeen)
	if err != nil {
		return nil, mapError(err)
	}
	return &a, nil
}

// AssetPage is a keyset page. Offset paging was avoided deliberately: the asset
// list has a p95 budget of 300ms at 10k assets, and OFFSET degrades linearly
// with depth on exactly the query that budget applies to.
type AssetPage struct {
	Assets []Asset
	// NextBefore is the cursor for the following page: pass it as `before`.
	// Zero when the page is the last one.
	NextBefore time.Time
	NextID     uuid.UUID
}

// AssetFilter narrows the asset list. Empty fields do not filter.
type AssetFilter struct {
	// Query matches a substring of the primary hostname OR of any current
	// address (asset_addresses with valid_to IS NULL). Empty matches all.
	Query string
	// Environment is an exact match on the environment tag. Empty matches all.
	Environment string
	// Fragile filters on the fragile flag when non-nil.
	Fragile *bool
	// AtRisk keeps only assets with an open or confirmed finding.
	AtRisk bool
	// SortByRisk orders by open-finding burden (KEV, then worst severity, then
	// count) instead of last seen. Keyset paging is disabled for that order:
	// callers get the first page of the worst, which is what a triage read wants.
	SortByRisk bool
}

// List returns assets newest-seen first, backed by the (tenant_id, last_seen DESC)
// index, narrowed by f. Pass a zero `before` for the first page.
func (Assets) List(ctx context.Context, c *Conn, f AssetFilter, before time.Time, beforeID uuid.UUID, limit int) (*AssetPage, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	// Search over hostname OR a current address, as an operator would type it.
	// The pattern is a bound parameter, never interpolated, so a value with %
	// or _ in it searches literally-enough and cannot alter the statement. The
	// address arm is an EXISTS over the current-addresses partial index rather
	// than a join, so a host with several addresses is not returned several
	// times.
	var qArg, envArg, fragileArg any
	if f.Query != "" {
		qArg = "%" + f.Query + "%"
	}
	if f.Environment != "" {
		envArg = f.Environment
	}
	if f.Fragile != nil {
		fragileArg = *f.Fragile
	}

	// The risk facts ride as lateral aggregates over the same findings rows
	// the finding list pages over, so a count here is a count the operator can
	// open. The advisory-status inputs mirror AdvisoryStatusInputs exactly.
	const q = `
		SELECT a.asset_id, coalesce(a.primary_hostname,''), coalesce(a.os_family,''),
		       coalesce(a.os_version,''), coalesce(a.device_type,''), coalesce(a.vendor,''),
		       a.criticality, coalesce(a.environment,''), coalesce(a.owner,''), a.fragile,
		       a.first_seen, a.last_seen,
		       coalesce((SELECT host(ad.ip_address) FROM asset_addresses ad
		                  WHERE ad.tenant_id = a.tenant_id AND ad.asset_id = a.asset_id AND ad.valid_to IS NULL
		                  ORDER BY ad.valid_from LIMIT 1), ''),
		       r.open, r.worst, r.kev, r.advisory,
		       a.distro_release IS NOT NULL,
		       (rc.esm_expires IS NOT NULL AND rc.esm_expires >= now()::date)
		  FROM assets a
		  LEFT JOIN release_coverage rc ON rc.distro_release = a.distro_release
		  CROSS JOIN LATERAL (
		    SELECT count(*)::int AS open,
		           coalesce(max(CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END), -1) AS worst,
		           count(*) FILTER (WHERE k.cve_id IS NOT NULL)::int AS kev,
		           bool_or(f.vuln_def_id IS NOT NULL) AS advisory
		      FROM findings f
		      LEFT JOIN vulnerability_defs vd ON vd.vuln_def_id = f.vuln_def_id
		      LEFT JOIN kev k ON k.cve_id = vd.cve_id
		     WHERE f.tenant_id = a.tenant_id AND f.asset_id = a.asset_id AND f.status IN ('open','confirmed')
		  ) r
		 WHERE a.tenant_id = $1
		   AND ($2::timestamptz IS NULL OR (a.last_seen, a.asset_id) < ($2, $3))
		   AND ($5::text IS NULL OR a.primary_hostname ILIKE $5 OR EXISTS (
		         SELECT 1 FROM asset_addresses aa
		          WHERE aa.tenant_id = a.tenant_id AND aa.asset_id = a.asset_id
		            AND aa.valid_to IS NULL AND host(aa.ip_address) ILIKE $5))
		   AND ($6::text IS NULL OR a.environment = $6)
		   AND ($7::boolean IS NULL OR a.fragile = $7)
		   AND (NOT $8::boolean OR r.open > 0)
		 ORDER BY CASE WHEN $9::boolean THEN r.kev END DESC NULLS LAST,
		          CASE WHEN $9::boolean THEN r.worst END DESC NULLS LAST,
		          CASE WHEN $9::boolean THEN r.open END DESC NULLS LAST,
		          a.last_seen DESC, a.asset_id DESC
		 LIMIT $4`

	var beforeArg any
	var beforeIDArg any = beforeID
	if !before.IsZero() && !f.SortByRisk {
		beforeArg = before
	}

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), beforeArg, beforeIDArg, limit, qArg, envArg, fragileArg, f.AtRisk, f.SortByRisk)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	page := &AssetPage{}
	for rows.Next() {
		var a Asset
		var worst int
		var advisory *bool
		if err := rows.Scan(&a.ID, &a.Hostname, &a.OSFamily, &a.OSVersion, &a.DeviceType,
			&a.Vendor, &a.Criticality, &a.Environment, &a.Owner, &a.Fragile,
			&a.FirstSeen, &a.LastSeen, &a.Address, &a.OpenFindings, &worst, &a.KEVFindings, &advisory,
			&a.ReleaseResolved, &a.InCoverage); err != nil {
			return nil, mapError(err)
		}
		if worst >= 0 {
			a.WorstSeverity = severityWord(worst)
		}
		a.HasAdvisoryFinding = advisory != nil && *advisory
		page.Assets = append(page.Assets, a)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(err)
	}
	if len(page.Assets) == limit && !f.SortByRisk {
		last := page.Assets[len(page.Assets)-1]
		page.NextBefore, page.NextID = last.LastSeen, last.ID
	}
	return page, nil
}

// TouchLastSeen advances last_seen. Called by derivation when an observation
// confirms an asset is still there.
// EnvironmentOf returns the asset's environment, or "" if unset.
//
// A thin read because the finding pipeline needs one field and building a whole
// Asset to get it would be wasteful on the hot path — every resolved host asks.
// Empty is NOT dev: the self-signed rule treats an un-tagged asset as
// production, because the safe default has to be the one that raises.
func (Assets) EnvironmentOf(ctx context.Context, c *Conn, id uuid.UUID) (string, error) {
	const q = `SELECT coalesce(environment,'') FROM assets WHERE tenant_id = $1 AND asset_id = $2`
	var env string
	if err := c.QueryRow(ctx, q, c.Tenant().UUID(), id).Scan(&env); err != nil {
		return "", mapError(err)
	}
	return env, nil
}

func (Assets) TouchLastSeen(ctx context.Context, c *Conn, id uuid.UUID, seenAt time.Time) error {
	const q = `
		UPDATE assets SET last_seen = greatest(last_seen, $3)
		 WHERE tenant_id = $1 AND asset_id = $2`

	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), id, seenAt)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetFragile marks an asset as rate-capped regardless of policy (ADR-024).
func (Assets) SetFragile(ctx context.Context, c *Conn, id uuid.UUID, fragile bool) error {
	const q = `UPDATE assets SET fragile = $3 WHERE tenant_id = $1 AND asset_id = $2`

	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), id, fragile)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetAttribution writes the OS attribution B21 derived (ADR-061). A nil
// distroRelease is the FAMILY-ONLY state — a distinct, real outcome — so it is
// stored as SQL NULL rather than coerced to a family the banner did not carry.
// provenance is the JSON chain of which services contributed, agreed and were
// ignored, cast to jsonb ($6::jsonb) so a []byte reaches the column as JSON
// rather than bytea.
//
// exact says whether this attribution was READ on the host (/etc/os-release,
// ADR-090) rather than inferred from banners. Provenance ranks regardless of
// recency (ADR-095): an inferred write lands only where no exact attribution is
// held — it fills an absence, it never overwrites — while an exact write always
// lands and is superseded only by a later exact read. The rank is enforced here,
// in the statement, so no later caller can forget it: the first fingerprint
// sweep after the credentialed run silently put .138 and .146 back to a 0.9
// band vote, and every further sweep would have kept doing it.
func (Assets) SetAttribution(ctx context.Context, c *Conn, id uuid.UUID, distroFamily string, distroRelease *string, confidence float32, provenance []byte, exact bool) error {
	if err := checkExactProvenance(exact, provenance, "os-release"); err != nil {
		return err
	}
	// distro_release is written by BOTH setters, so its arm here also honours an
	// exact release_provenance: an inferred family write must not null or
	// replace a release a credentialed read established.
	// The rank is read from the row's OWN columns inside the SET (pre-update
	// values), not from a subselect: a subselect is evaluated against the
	// statement snapshot and is not re-read when the row lock is granted, so
	// an inferred write waiting behind a concurrent exact write would land on
	// top of it. Self-referential, the CASE sees the committed row.
	const q = `UPDATE assets
	     SET distro_family = CASE WHEN (NOT $7::bool) AND jsonb_typeof(os_provenance) = 'object' AND os_provenance ->> 'source' = 'os-release'
	                             THEN distro_family ELSE nullif($3,'') END,
	         distro_release = CASE WHEN (NOT $7::bool) AND ((jsonb_typeof(os_provenance) = 'object' AND os_provenance ->> 'source' = 'os-release')
	                                                     OR (jsonb_typeof(release_provenance) = 'object' AND release_provenance ->> 'source' = 'package_manager'))
	                             THEN distro_release ELSE $4 END,
	         os_confidence = CASE WHEN (NOT $7::bool) AND jsonb_typeof(os_provenance) = 'object' AND os_provenance ->> 'source' = 'os-release'
	                             THEN os_confidence ELSE $5 END,
	         os_provenance = CASE WHEN (NOT $7::bool) AND jsonb_typeof(os_provenance) = 'object' AND os_provenance ->> 'source' = 'os-release'
	                             THEN os_provenance ELSE $6::jsonb END
	   WHERE tenant_id = $1 AND asset_id = $2`

	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), id, distroFamily, distroRelease, confidence, string(provenance), exact)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// checkExactProvenance keeps the two statements of one fact in step: the rank a
// caller claims (exact) and the provenance shape the guard reads back. An exact
// write must carry the canonical object with the source the guard looks for,
// or a later inferred write would find nothing to hold and overwrite it.
func checkExactProvenance(exact bool, provenance []byte, source string) error {
	if !exact {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(provenance, &m); err != nil {
		return fmt.Errorf("store: exact attribution needs an object provenance: %w", err)
	}
	if got, _ := m["source"].(string); got != source {
		return fmt.Errorf("store: exact attribution provenance source = %q, want %q", got, source)
	}
	return nil
}

// ReleaseOf returns what the asset HOLDS as its release and confidence after the
// ranked writes above — which is what advisory matching must key on (ADR-095):
// a band vote the store refused to record must not be the release the same
// sweep matches advisories against.
//
// found is false when the asset holds no release, or holds one with no
// confidence: a release without a confidence cannot compose a finding's
// confidence honestly (0.0 would be legal and invisible), so the caller keeps
// its own value in that case rather than inheriting a zero.
func (Assets) ReleaseOf(ctx context.Context, c *Conn, id uuid.UUID) (release string, confidence float32, found bool, err error) {
	var rel *string
	var conf *float32
	if err := c.QueryRow(ctx, `SELECT distro_release, release_confidence FROM assets WHERE tenant_id = $1 AND asset_id = $2`,
		c.Tenant().UUID(), id).Scan(&rel, &conf); err != nil {
		return "", 0, false, mapError(err)
	}
	if rel == nil || conf == nil {
		return "", 0, false, nil
	}
	return *rel, *conf, true, nil
}

// FamilyOf reads the asset's attributed distro family ("" when unattributed):
// ADR-096's OS-agreement fact compares it against what a contested sighting's
// banners attribute.
func (Assets) FamilyOf(ctx context.Context, c *Conn, id uuid.UUID) (string, error) {
	var fam *string
	if err := c.QueryRow(ctx, `SELECT distro_family FROM assets WHERE tenant_id = $1 AND asset_id = $2`,
		c.Tenant().UUID(), id).Scan(&fam); err != nil {
		return "", mapError(err)
	}
	if fam == nil {
		return "", nil
	}
	return *fam, nil
}

// SetRelease records the release resolution on the asset (P3.3, ADR-064):
// distro_release (nil when UNRESOLVED — family-only stays the state, ADR-061),
// its confidence, and its provenance chain. Separate from SetAttribution because
// release is resolved in a second step, from the advisory keyspace, after the
// family is known — and its evidence (which services voted, agreed, abstained) is
// distinct from the family's, so it lands in its own column. The provenance is
// stored EVEN WHEN UNRESOLVED, so an operator can see why it did not resolve
// (which services abstained and why) rather than facing a silent family-only.
// Guarded by distro_family IS NOT NULL: resolution runs only under a known family.
//
// exact ranks the write as SetAttribution's does (ADR-095): a band vote never
// overwrites a release read from the host; it only fills an absence.
func (Assets) SetRelease(ctx context.Context, c *Conn, id uuid.UUID, release *string, confidence float32, provenance []byte, exact bool) error {
	if err := checkExactProvenance(exact, provenance, "package_manager"); err != nil {
		return err
	}
	const q = `UPDATE assets
	     SET distro_release = CASE WHEN (NOT $6::bool) AND jsonb_typeof(release_provenance) = 'object' AND release_provenance ->> 'source' = 'package_manager'
	                             THEN distro_release ELSE $3 END,
	         release_confidence = CASE WHEN (NOT $6::bool) AND jsonb_typeof(release_provenance) = 'object' AND release_provenance ->> 'source' = 'package_manager'
	                             THEN release_confidence ELSE $4 END,
	         release_provenance = CASE WHEN (NOT $6::bool) AND jsonb_typeof(release_provenance) = 'object' AND release_provenance ->> 'source' = 'package_manager'
	                             THEN release_provenance ELSE $5::jsonb END
	   WHERE tenant_id = $1 AND asset_id = $2 AND distro_family IS NOT NULL`

	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), id, release, confidence, string(provenance), exact)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		// No family on the asset: release resolution runs only under a known
		// family, so this is a caller ordering bug, not a missing row.
		return ErrNotFound
	}
	return nil
}

// ============================================================================
// Asset detail (session 18): the base row plus its current addresses and
// services, for the operator UI's asset view.
// ============================================================================

// AssetAddress is one current address of an asset (valid_to IS NULL). Held as
// text — host(ip) and mac::text — because the API renders it and never does
// arithmetic on it.
type AssetAddress struct {
	IP        string
	MAC       string
	ValidFrom time.Time
}

// AssetService is one listening endpoint on an asset.
type AssetService struct {
	Port       int
	Protocol   string
	Service    string
	Product    string
	Version    string
	Confidence *float64 // nil when the version was not inferred with a confidence
	Method     string   // banner, probe, tls, ... — how the identification was learned
	LastSeen   time.Time
}

// AssetDetail is one asset with everything the UI shows on its page.
type AssetDetail struct {
	Asset
	Addresses    []AssetAddress
	Services     []AssetService
	OpenFindings int

	// OS attribution (ADR-061). DistroFamily "" is no attribution; DistroFamily
	// set with DistroRelease nil is family-only ("Ubuntu, no feed"); both set is
	// resolved. OSProvenance is the chain of which services contributed, agreed
	// and were ignored — a claim's evidence, reachable on the asset page.
	DistroFamily  string
	DistroRelease *string
	OSConfidence  *float64
	OSProvenance  json.RawMessage

	// Release resolution (ADR-064). DistroRelease above is the outcome (nil =
	// unresolved/family-only); these are its OWN confidence and evidence chain —
	// which services voted, agreed, and abstained (with why), distinct from the
	// family provenance. Present even when unresolved, so the asset page can show
	// why a release did not resolve rather than a silent family-only.
	ReleaseConfidence *float64
	ReleaseProvenance json.RawMessage

	// Advisory coverage for the resolved release (B29, ADR-067). State is
	// covered / out_of_coverage / unknown, nil when there is no release. When
	// out_of_coverage, a "clean" (no advisory) result on this host means
	// cannot-know, and the asset page must say so — a finding list that shows
	// nothing here is otherwise indistinguishable from one that could not be
	// assessed. ReleaseCoverageEnd is the effective last-covered date (the newest
	// advisory the keyspace holds for the release, or the feed's ESM date).
	ReleaseCoverageState *string
	ReleaseCoverageEnd   *time.Time

	// HasOpenAdvisoryFinding is whether any open finding carries a vuln_def_id
	// (an advisory match). Input to the advisory_status enum (ADR-068). Always
	// false until P3.4 produces advisory findings; queried, not assumed, so the
	// vulnerable state activates automatically when it does.
	HasOpenAdvisoryFinding bool
}

// GetDetail returns the full asset view, or ErrNotFound (also what a
// cross-tenant id gives — indistinguishable under RLS, deliberately).
func (Assets) GetDetail(ctx context.Context, c *Conn, id uuid.UUID) (*AssetDetail, error) {
	base, err := (Assets{}).GetByID(ctx, c, id)
	if err != nil {
		return nil, err
	}
	d := &AssetDetail{Asset: *base}

	const addrQ = `
		SELECT coalesce(host(ip_address), ''), coalesce(mac_address::text, ''), valid_from
		  FROM asset_addresses
		 WHERE tenant_id = $1 AND asset_id = $2 AND valid_to IS NULL
		 ORDER BY valid_from`
	rows, err := c.Query(ctx, addrQ, c.Tenant().UUID(), id)
	if err != nil {
		return nil, mapError(err)
	}
	for rows.Next() {
		var a AssetAddress
		if err := rows.Scan(&a.IP, &a.MAC, &a.ValidFrom); err != nil {
			rows.Close()
			return nil, mapError(err)
		}
		d.Addresses = append(d.Addresses, a)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, mapError(err)
	}
	rows.Close()

	const svcQ = `
		SELECT port, protocol, coalesce(service_name,''), coalesce(product,''),
		       coalesce(version,''), version_confidence, coalesce(identification_method,''), last_seen
		  FROM services
		 WHERE tenant_id = $1 AND asset_id = $2
		 ORDER BY port, protocol`
	srows, err := c.Query(ctx, svcQ, c.Tenant().UUID(), id)
	if err != nil {
		return nil, mapError(err)
	}
	for srows.Next() {
		var s AssetService
		if err := srows.Scan(&s.Port, &s.Protocol, &s.Service, &s.Product,
			&s.Version, &s.Confidence, &s.Method, &s.LastSeen); err != nil {
			srows.Close()
			return nil, mapError(err)
		}
		d.Services = append(d.Services, s)
	}
	if err := srows.Err(); err != nil {
		srows.Close()
		return nil, mapError(err)
	}
	srows.Close()

	const cntQ = `
		SELECT count(*),
		       count(*) FILTER (WHERE vuln_def_id IS NOT NULL) > 0
		  FROM findings
		 WHERE tenant_id = $1 AND asset_id = $2 AND status IN ('open','confirmed')`
	if err := c.QueryRow(ctx, cntQ, c.Tenant().UUID(), id).
		Scan(&d.OpenFindings, &d.HasOpenAdvisoryFinding); err != nil {
		return nil, mapError(err)
	}

	const osQ = `
		SELECT coalesce(a.distro_family,''), a.distro_release, a.os_confidence, a.os_provenance,
		       a.release_confidence, a.release_provenance,
		       CASE WHEN a.distro_release IS NULL THEN NULL
		            WHEN rc.esm_expires IS NULL THEN 'unknown'
		            WHEN rc.esm_expires < now()::date THEN 'out_of_coverage'
		            ELSE 'covered' END AS coverage_state,
		       COALESCE(
		           (SELECT max(va.issued_at)::date FROM advisory_fixed_packages afp
		              JOIN vendor_advisories va USING (advisory_id)
		             WHERE afp.distro_release = a.distro_release),
		           rc.esm_expires) AS coverage_end
		  FROM assets a
		  LEFT JOIN release_coverage rc ON rc.distro_release = a.distro_release
		 WHERE a.tenant_id = $1 AND a.asset_id = $2`
	if err := c.QueryRow(ctx, osQ, c.Tenant().UUID(), id).
		Scan(&d.DistroFamily, &d.DistroRelease, &d.OSConfidence, &d.OSProvenance,
			&d.ReleaseConfidence, &d.ReleaseProvenance,
			&d.ReleaseCoverageState, &d.ReleaseCoverageEnd); err != nil {
		return nil, mapError(err)
	}
	return d, nil
}

// AdvisoryStatusInputs returns the three inputs to an asset's advisory_status
// (ADR-068): whether a release is resolved, whether it is in advisory coverage,
// and whether any open advisory finding exists. The verdict itself is
// domain.AssetAdvisoryStatus (the caller applies it) — the store gathers, the
// domain decides. ErrNotFound if the asset is not the caller's.
func (Assets) AdvisoryStatusInputs(ctx context.Context, c *Conn, id uuid.UUID) (releaseResolved, inCoverage, hasAdvisoryFinding bool, err error) {
	const q = `
		SELECT a.distro_release IS NOT NULL,
		       (rc.esm_expires IS NOT NULL AND rc.esm_expires >= now()::date),
		       EXISTS (SELECT 1 FROM findings f
		                WHERE f.tenant_id = $1 AND f.asset_id = $2
		                  AND f.status IN ('open','confirmed') AND f.vuln_def_id IS NOT NULL)
		  FROM assets a
		  LEFT JOIN release_coverage rc ON rc.distro_release = a.distro_release
		 WHERE a.tenant_id = $1 AND a.asset_id = $2`
	err = c.QueryRow(ctx, q, c.Tenant().UUID(), id).Scan(&releaseResolved, &inCoverage, &hasAdvisoryFinding)
	return releaseResolved, inCoverage, hasAdvisoryFinding, mapError(err)
}

// AssetExportRowCap bounds a CSV export of assets, the asset analogue of
// findings' cap: an export over it is refused, never truncated, so an incomplete
// file cannot pass for complete.
const AssetExportRowCap = 50000

// ListForExport returns up to `max` assets matching the filter, newest-seen
// first, with no cursor — the whole set for a CSV. Callers pass the cap+1 and
// refuse when the result exceeds the cap. Ordered (last_seen, asset_id) so the
// bounded set is deterministic, not an arbitrary LIMIT slice.
func (Assets) ListForExport(ctx context.Context, c *Conn, f AssetFilter, max int) ([]Asset, error) {
	if max <= 0 || max > AssetExportRowCap+1 {
		max = AssetExportRowCap + 1
	}
	var qArg, envArg, fragileArg any
	if f.Query != "" {
		qArg = "%" + f.Query + "%"
	}
	if f.Environment != "" {
		envArg = f.Environment
	}
	if f.Fragile != nil {
		fragileArg = *f.Fragile
	}

	const q = `
		SELECT asset_id, coalesce(primary_hostname,''), coalesce(os_family,''),
		       coalesce(os_version,''), coalesce(device_type,''), coalesce(vendor,''),
		       criticality, coalesce(environment,''), coalesce(owner,''), fragile,
		       first_seen, last_seen
		  FROM assets
		 WHERE tenant_id = $1
		   AND ($2::text IS NULL OR primary_hostname ILIKE $2 OR EXISTS (
		         SELECT 1 FROM asset_addresses aa
		          WHERE aa.tenant_id = assets.tenant_id AND aa.asset_id = assets.asset_id
		            AND aa.valid_to IS NULL AND host(aa.ip_address) ILIKE $2))
		   AND ($3::text IS NULL OR environment = $3)
		   AND ($4::boolean IS NULL OR fragile = $4)
		 ORDER BY last_seen DESC, asset_id DESC
		 LIMIT $5`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), qArg, envArg, fragileArg, max)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []Asset
	for rows.Next() {
		var a Asset
		if err := rows.Scan(&a.ID, &a.Hostname, &a.OSFamily, &a.OSVersion, &a.DeviceType,
			&a.Vendor, &a.Criticality, &a.Environment, &a.Owner, &a.Fragile,
			&a.FirstSeen, &a.LastSeen); err != nil {
			return nil, mapError(err)
		}
		out = append(out, a)
	}
	return out, mapError(rows.Err())
}
