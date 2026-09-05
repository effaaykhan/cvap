package load

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/store"
)

// seedOpts controls the synthetic seed's scale and exposure distribution.
type seedOpts struct {
	assets   int
	findings int
	// avgExposure is the target mean of finding_exposure rows per finding.
	// 1.0 is production reality today (one vantage per finding); ~2.4 is the
	// ADR-010 multi-vantage case the pipeline has never actually produced but
	// the exposure aggregation must survive. Session 21's reason for measuring
	// both.
	avgExposure float64
	zones       int
}

// seedSynthetic writes assets/findings/keys/addresses/exposure DIRECTLY, matched
// to the shape TestMeasureRealShape measured (see shape_match_test): empty assets
// (all optional columns NULL), moderate-only (strength 2) keys at 0/1/2 per asset
// ~20/60/20, one live address each, findings clustered 1-or-4 per endpoint, and
// vuln_def_id always NULL. ADR-006 makes correlate the only asset writer in
// production; a load-test seeder writing directly is fine (task-scoped).
func seedSynthetic(t *testing.T, db *store.DB, tenant store.TenantID, o seedOpts) {
	t.Helper()
	if o.zones == 0 {
		o.zones = 5
	}
	ctx := context.Background()

	// Zones for exposure rows, and the rule ids findings reference (global table).
	var zoneIDs []uuid.UUID
	var ruleIDs []uuid.UUID
	var ruleNames []string
	var ruleSev []string
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		for i := 0; i < o.zones; i++ {
			z, err := (store.Zones{}).Create(ctx, c, fmt.Sprintf("z%d", i), store.ZoneInternal, 1, "")
			if err != nil {
				return err
			}
			zoneIDs = append(zoneIDs, z.ID)
		}
		rows, err := c.Query(ctx, `SELECT rule_id, name, default_severity FROM rules ORDER BY name`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			var name, sev string
			if err := rows.Scan(&id, &name, &sev); err != nil {
				return err
			}
			ruleIDs = append(ruleIDs, id)
			ruleNames = append(ruleNames, name)
			ruleSev = append(ruleSev, sev)
		}
		return rows.Err()
	}); err != nil {
		t.Fatalf("seed zones/rules: %v", err)
	}
	if len(ruleIDs) == 0 {
		t.Fatal("no rules to reference; run migrations (0032 builtin pack)")
	}

	// --- assets: empty, varied last_seen so the keyset ORDER BY has a real spread
	assetIDs := make([]uuid.UUID, o.assets)
	firstSeen := make([]time.Time, o.assets)
	lastSeen := make([]time.Time, o.assets)
	base := time.Now().Add(-time.Hour)
	for i := range assetIDs {
		assetIDs[i] = uuid.New()
		lastSeen[i] = base.Add(-time.Duration(i) * time.Second)
		firstSeen[i] = lastSeen[i].Add(-24 * time.Hour)
	}
	insertBatched(t, db, tenant, o.assets, 5000, func(lo, hi int) (string, []any) {
		return `INSERT INTO assets (tenant_id, asset_id, first_seen, last_seen)
		        SELECT $1, unnest($2::uuid[]), unnest($3::timestamptz[]), unnest($4::timestamptz[])`,
			[]any{tenant.UUID(), assetIDs[lo:hi], firstSeen[lo:hi], lastSeen[lo:hi]}
	})

	// --- addresses: one live per asset, unique IP
	addrIPs := make([]string, o.assets)
	for i := range addrIPs {
		addrIPs[i] = fmt.Sprintf("10.%d.%d.%d", (i>>16)&255, (i>>8)&255, i&255)
	}
	insertBatched(t, db, tenant, o.assets, 5000, func(lo, hi int) (string, []any) {
		return `INSERT INTO asset_addresses (tenant_id, asset_id, ip_address, valid_from)
		        SELECT $1, unnest($2::uuid[]), unnest($3::text[])::inet, unnest($4::timestamptz[])`,
			[]any{tenant.UUID(), assetIDs[lo:hi], addrIPs[lo:hi], firstSeen[lo:hi]}
	})

	// --- identity keys: moderate (strength 2), 0/1/2 per asset ~20/60/20
	var kAsset []uuid.UUID
	var kType []string
	var kValue []string
	moderate := []string{"ssh_hostkey", "service_cert_fp"}
	for i, a := range assetIDs {
		n := 1
		switch i % 5 {
		case 0:
			n = 0
		case 4:
			n = 2
		}
		for j := 0; j < n; j++ {
			kAsset = append(kAsset, a)
			kType = append(kType, moderate[j%2])
			kValue = append(kValue, fmt.Sprintf("k-%s-%d", a, j))
		}
	}
	insertBatched(t, db, tenant, len(kAsset), 5000, func(lo, hi int) (string, []any) {
		return `INSERT INTO asset_identity_keys (tenant_id, asset_id, key_type, key_value, strength)
		        SELECT $1, unnest($2::uuid[]), unnest($3::identity_key_type[]), unnest($4::text[]), 2`,
			[]any{tenant.UUID(), kAsset[lo:hi], kType[lo:hi], kValue[lo:hi]}
	})

	// --- findings: clustered 1-or-4 per endpoint, unique dedup, vuln_def_id NULL
	fIDs := make([]uuid.UUID, 0, o.findings)
	var fAsset []uuid.UUID
	var fRule []uuid.UUID
	var fSev []string
	var fDedup []string
	var fLoc []string
	var fLast []time.Time
	ep := 0
	for len(fIDs) < o.findings {
		asset := assetIDs[ep%o.assets]
		port := 1 + ep // unique per endpoint -> unique dedup
		cluster := 1
		if ep%3 != 0 { // ~2/3 of endpoints get 4 findings, ~1/3 get 1 (matches 1:57 4:115)
			cluster = 4
		}
		for r := 0; r < cluster && len(fIDs) < o.findings; r++ {
			id := uuid.New()
			fIDs = append(fIDs, id)
			fAsset = append(fAsset, asset)
			fRule = append(fRule, ruleIDs[r%len(ruleIDs)])
			fSev = append(fSev, ruleSev[r%len(ruleSev)])
			fDedup = append(fDedup, fmt.Sprintf("network|%s|%d|tcp|%s", asset, port, ruleNames[r%len(ruleNames)]))
			fLoc = append(fLoc, fmt.Sprintf("%d/tcp", port))
			fLast = append(fLast, base.Add(-time.Duration(len(fIDs))*time.Second))
		}
		ep++
	}
	insertBatched(t, db, tenant, len(fIDs), 4000, func(lo, hi int) (string, []any) {
		return `INSERT INTO findings (tenant_id, finding_id, asset_id, rule_id, source, dedup_key,
		                              severity, confidence, instance_locator, status, first_seen, last_seen)
		        SELECT $1, unnest($2::uuid[]), unnest($3::uuid[]), unnest($4::uuid[]), 'network',
		               unnest($5::text[]), unnest($6::severity[]), 0.9, unnest($7::text[]), 'open',
		               unnest($8::timestamptz[]), unnest($8::timestamptz[])`,
			[]any{tenant.UUID(), fIDs[lo:hi], fAsset[lo:hi], fRule[lo:hi], fDedup[lo:hi],
				fSev[lo:hi], fLoc[lo:hi], fLast[lo:hi]}
	})

	// --- exposure: nZones per finding, drawn to hit the target mean
	var eFind []uuid.UUID
	var eZone []uuid.UUID
	for i, id := range fIDs {
		n := exposureCount(o.avgExposure, i)
		if n > len(zoneIDs) {
			n = len(zoneIDs)
		}
		for z := 0; z < n; z++ {
			eFind = append(eFind, id)
			eZone = append(eZone, zoneIDs[z])
		}
	}
	insertBatched(t, db, tenant, len(eFind), 5000, func(lo, hi int) (string, []any) {
		return `INSERT INTO finding_exposure (tenant_id, finding_id, zone_id)
		        SELECT $1, unnest($2::uuid[]), unnest($3::uuid[])`,
			[]any{tenant.UUID(), eFind[lo:hi], eZone[lo:hi]}
	})
}

// exposureCount returns how many zones this finding is exposed from, drawn so the
// mean approaches avg. avg==1 gives exactly 1 (production reality); ~2.4 gives a
// 1/2/3/4 spread whose mean is ~2.4.
func exposureCount(avg float64, i int) int {
	if avg <= 1.0 {
		return 1
	}
	// 20% 1, 30% 2, 30% 3, 20% 4 -> mean 2.5
	switch i % 10 {
	case 0, 1:
		return 1
	case 2, 3, 4:
		return 2
	case 5, 6, 7:
		return 3
	default:
		return 4
	}
}

// insertBatched runs fn over [0,total) in chunks, each inside its own Write.
func insertBatched(t *testing.T, db *store.DB, tenant store.TenantID, total, chunk int,
	fn func(lo, hi int) (string, []any)) {
	t.Helper()
	for lo := 0; lo < total; lo += chunk {
		hi := lo + chunk
		if hi > total {
			hi = total
		}
		q, args := fn(lo, hi)
		if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
			_, err := c.Exec(ctx, q, args...)
			return err
		}); err != nil {
			t.Fatalf("batch insert [%d,%d): %v", lo, hi, err)
		}
	}
}
