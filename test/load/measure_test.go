package load

import (
	"context"
	"io"
	"log/slog"
	"sort"
	"testing"

	"github.com/effaaykhan/cvap/internal/store"
)

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// measureShape reads the five distributions the load-test seed must reproduce.
func measureShape(t *testing.T, db *store.DB, tenant store.TenantID) shape {
	t.Helper()
	sh := shape{
		keysPerAsset:     map[int]int{},
		strengths:        map[int]int{},
		exposurePerFind:  map[int]int{},
		findingsPerEndpt: map[int]int{},
		currentAddrs:     map[int]int{},
	}
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		tid := tenant.UUID()

		if err := c.QueryRow(ctx, `SELECT count(*) FROM assets WHERE tenant_id=$1`, tid).Scan(&sh.assets); err != nil {
			return err
		}
		if err := c.QueryRow(ctx, `SELECT count(*) FROM findings WHERE tenant_id=$1`, tid).Scan(&sh.findings); err != nil {
			return err
		}
		if err := c.QueryRow(ctx,
			`SELECT count(*) FROM assets WHERE tenant_id=$1
			   AND primary_hostname IS NULL AND os_family IS NULL AND os_version IS NULL
			   AND device_type IS NULL AND vendor IS NULL AND environment IS NULL AND owner IS NULL`,
			tid).Scan(&sh.assetsNullOptional); err != nil {
			return err
		}
		if err := c.QueryRow(ctx,
			`SELECT count(*) FROM findings WHERE tenant_id=$1 AND vuln_def_id IS NULL`,
			tid).Scan(&sh.findingsNullVuln); err != nil {
			return err
		}

		// keys per asset (live), including assets with zero stored keys via a LEFT JOIN.
		if err := scanBuckets(ctx, c, sh.keysPerAsset,
			`SELECT k.n, count(*) FROM (
			    SELECT a.asset_id, count(ik.identity_key_id) AS n
			      FROM assets a
			      LEFT JOIN asset_identity_keys ik
			        ON ik.tenant_id=a.tenant_id AND ik.asset_id=a.asset_id AND ik.valid_to IS NULL
			     WHERE a.tenant_id=$1 GROUP BY a.asset_id) k
			 GROUP BY k.n`); err != nil {
			return err
		}
		if err := scanBuckets(ctx, c, sh.strengths,
			`SELECT strength, count(*) FROM asset_identity_keys
			  WHERE tenant_id=$1 AND valid_to IS NULL GROUP BY strength`); err != nil {
			return err
		}
		if err := scanBuckets(ctx, c, sh.exposurePerFind,
			`SELECT e.n, count(*) FROM (
			    SELECT finding_id, count(*) AS n FROM finding_exposure
			     WHERE tenant_id=$1 GROUP BY finding_id) e GROUP BY e.n`); err != nil {
			return err
		}
		if err := scanBuckets(ctx, c, sh.findingsPerEndpt,
			`SELECT g.n, count(*) FROM (
			    SELECT split_part(dedup_key,'|',2), split_part(dedup_key,'|',3),
			           split_part(dedup_key,'|',4), count(*) AS n
			      FROM findings WHERE tenant_id=$1 GROUP BY 1,2,3) g GROUP BY g.n`); err != nil {
			return err
		}
		if err := scanBuckets(ctx, c, sh.currentAddrs,
			`SELECT a.n, count(*) FROM (
			    SELECT asset_id, count(*) FILTER (WHERE valid_to IS NULL) AS n
			      FROM asset_addresses WHERE tenant_id=$1 GROUP BY asset_id) a GROUP BY a.n`); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatalf("measure shape: %v", err)
	}
	return sh
}

func scanBuckets(ctx context.Context, c *store.Conn, into map[int]int, q string, args ...any) error {
	if len(args) == 0 {
		args = []any{c.Tenant().UUID()}
	}
	rows, err := c.Query(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var k, v int
		if err := rows.Scan(&k, &v); err != nil {
			return err
		}
		into[k] = v
	}
	return rows.Err()
}

func reportShape(t *testing.T, label string, sh shape) {
	t.Helper()
	t.Logf("=== %s shape: %d assets, %d findings ===", label, sh.assets, sh.findings)
	t.Logf("  keys/asset:        %s", buckets(sh.keysPerAsset))
	t.Logf("  key strengths:     %s", buckets(sh.strengths))
	t.Logf("  exposure/finding:  %s", buckets(sh.exposurePerFind))
	t.Logf("  findings/endpoint: %s", buckets(sh.findingsPerEndpt))
	t.Logf("  current addrs:     %s", buckets(sh.currentAddrs))
	t.Logf("  assets all-optional-NULL: %d/%d; findings vuln_def_id NULL: %d/%d",
		sh.assetsNullOptional, sh.assets, sh.findingsNullVuln, sh.findings)
}

func buckets(m map[int]int) string {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	out := ""
	for _, k := range keys {
		out += " " + itoa(k) + ":" + itoa(m[k])
	}
	if out == "" {
		return "(none)"
	}
	return out[1:]
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}
