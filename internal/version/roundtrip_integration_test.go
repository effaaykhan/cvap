package version_test

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/store"
	"github.com/effaaykhan/cvap/internal/version"
)

// TestPostgresRoundTripGoIsAuthoritative is the two-writers-one-fact guard
// (§5.2, ADR-062): the second writer of a version verdict would be the database,
// and a comparator correct in Go that disagrees with SQL doing the same
// comparison is the defect that ships silently. So this proves two things against
// a real Postgres:
//
//  1. Version strings round-trip byte-identical — the DB neither truncates nor
//     mangles them, so what Go compares is what was stored.
//  2. SQL's native text ordering DISAGREES with dpkg semantics — it sorts a
//     pre-release AFTER its release — which is exactly why the database must not
//     be allowed to decide the comparison. Go is authoritative; SQL may only
//     narrow the candidate set (ADR-062).
func TestPostgresRoundTripGoIsAuthoritative(t *testing.T) {
	url := os.Getenv("CVAP_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CVAP_TEST_DATABASE_URL not set")
	}
	db, err := store.Open(context.Background(), store.Config{URL: url})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(db.Close)

	// The set includes the tilde pre-release and the real backport strings.
	inserted := []string{"1.0", "1.0~rc1", "1.0-1", "2.2.8", "2.2.8-1ubuntu0.22"}
	tenant, err := store.NewTenantID(uuid.New())
	if err != nil {
		t.Fatal(err)
	}

	var sqlTextOrder []string // as Postgres text-sorts them — deliberately the WRONG order
	got := map[string]bool{}
	err = db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		// A temp table with no RLS/FK: this tests the database's own text handling
		// and ordering, not a tenant-scoped table.
		if _, err := c.Exec(ctx, `CREATE TEMP TABLE vtest (v text) ON COMMIT DROP`); err != nil {
			return err
		}
		for _, v := range inserted {
			if _, err := c.Exec(ctx, `INSERT INTO vtest (v) VALUES ($1)`, v); err != nil {
				return err
			}
		}
		rows, err := c.Query(ctx, `SELECT v FROM vtest ORDER BY v`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				return err
			}
			sqlTextOrder = append(sqlTextOrder, v)
			got[v] = true
		}
		return rows.Err()
	})
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}

	// 1. Round-trip fidelity: every string comes back byte-identical.
	for _, v := range inserted {
		if !got[v] {
			t.Errorf("version %q did not round-trip through Postgres intact", v)
		}
	}
	if len(sqlTextOrder) != len(inserted) {
		t.Fatalf("stored %d versions, read back %d", len(inserted), len(sqlTextOrder))
	}

	// 2. SQL text ordering disagrees with Go on the tilde. In Postgres text order
	// "1.0" precedes "1.0~rc1" (a shorter prefix sorts first); dpkg is the
	// opposite — a pre-release is OLDER than its release.
	posRelease, posPre := indexOf(sqlTextOrder, "1.0"), indexOf(sqlTextOrder, "1.0~rc1")
	if posRelease >= posPre {
		t.Fatalf("expected Postgres text sort to put 1.0 before 1.0~rc1 (the disagreement this test relies on); order was %v", sqlTextOrder)
	}
	if version.CompareDpkg("1.0~rc1", "1.0") != -1 {
		t.Fatal("Go dpkg must sort 1.0~rc1 BELOW 1.0")
	}
	// The two disagree — proven — therefore the database must not decide version
	// comparison; Go is the single authority. If a future query does version
	// comparison in SQL, it must be differential-tested against Go, not trusted.
	t.Logf("confirmed: Postgres text order %v disagrees with dpkg on the tilde; Go is authoritative (ADR-062)", sqlTextOrder)
}

func indexOf(ss []string, want string) int {
	for i, s := range ss {
		if s == want {
			return i
		}
	}
	return -1
}
