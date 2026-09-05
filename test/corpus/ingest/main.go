// Command corpus-ingest drives observations through the REAL Core pipeline and
// prints what it produced, for make corpus-check to diff against the golden
// corpus.
//
// ============================================================================
// It runs the actual correlator and the migration-seeded rules, not a copy.
// ============================================================================
//
// The scanner half of corpus-check runs the real discovery and fingerprint
// engines in containers against the lab and captures their observations. This
// program takes those observations, inserts them for a fresh tenant exactly as
// ingest would, runs correlate.SweepOnce, and dumps the resulting assets,
// services and findings as JSON. Nothing here decides anything a rule or the
// correlator would — the point is to exercise them, so the diff measures the
// product rather than a reimplementation of it.
//
// It reads a plan on stdin and writes a result on stdout, so the Python driver
// that owns the container orchestration and the metric arithmetic never needs a
// database driver of its own.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/correlate"
	"github.com/effaaykhan/cvap/internal/store"
)

// plan is what the driver sends.
type plan struct {
	// Scan: observations grouped by the zone TYPE they were seen from. The
	// driver ran the engines from a scan point in each segment and tags each
	// batch with that segment's zone type.
	Scan map[string][]obsIn `json:"scan"`

	// Merge scenarios: synthetic observation sequences with an expected asset
	// count, labelled by construction (ADR-007's designed outcomes).
	Merge []mergeScenario `json:"merge"`
}

type obsIn struct {
	Type    string `json:"type"`
	Payload string `json:"payload"` // base64 of the observation jsonb
	Task    string `json:"task"`    // opaque; the driver groups by it if it wants
}

type mergeScenario struct {
	Name         string     `json:"name"`
	Observations []mergeObs `json:"observations"`
	Expected     int        `json:"expected_assets"`
}

type mergeObs struct {
	Address string `json:"address"`
	SSHfp   string `json:"ssh_fp"`
	CertFP  string `json:"cert_fp"`
}

// result is what the driver reads back.
type result struct {
	Findings []findingOut `json:"findings"`
	Merge    []mergeOut   `json:"merge"`
}

type findingOut struct {
	Rule    string `json:"rule"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	Zones   int    `json:"zones"`
	Status  string `json:"status"`
	// EvidenceKeys is the key count of this finding's richest evidence row. Zero
	// means no verifiable evidence; corpus-check asserts every finding has > 0
	// (session 19, note on ADR-006).
	EvidenceKeys int `json:"evidence_keys"`
}

type mergeOut struct {
	Name     string `json:"name"`
	Assets   int    `json:"assets"`
	Expected int    `json:"expected"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "corpus-ingest:", err)
		os.Exit(1)
	}
}

func run() error {
	url := os.Getenv("APP_DATABASE_URL")
	if url == "" {
		return fmt.Errorf("APP_DATABASE_URL is not set")
	}
	var p plan
	if err := json.NewDecoder(os.Stdin).Decode(&p); err != nil {
		return fmt.Errorf("reading plan: %w", err)
	}

	ctx := context.Background()
	db, err := store.Open(ctx, store.Config{URL: url})
	if err != nil {
		return err
	}
	defer db.Close()

	var res result

	// ---- the lab scan ----
	if len(p.Scan) > 0 {
		fs, err := ingestScan(ctx, db, p.Scan)
		if err != nil {
			return err
		}
		res.Findings = fs
	}

	// ---- the merge scenarios ----
	for _, m := range p.Merge {
		n, err := runMerge(ctx, db, m)
		if err != nil {
			return err
		}
		res.Merge = append(res.Merge, mergeOut{Name: m.Name, Assets: n, Expected: m.Expected})
	}

	return json.NewEncoder(os.Stdout).Encode(res)
}

// ingestScan inserts every observation for a fresh tenant, one zone per zone
// type, runs the correlator, and reads back the findings.
func ingestScan(ctx context.Context, db *store.DB, byZone map[string][]obsIn) ([]findingOut, error) {
	tenant, err := freshTenant(ctx, db, "corpus-scan")
	if err != nil {
		return nil, err
	}
	spID, subID, taskID, zoneIDs, err := seedScaffold(ctx, db, tenant, byZone)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()

	// Observations are timestamped in the past so they sit inside the sweep's
	// observed_at < now window — the boundary session 15's tests learned to
	// respect.
	at := now.Add(-time.Hour)
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		for zt, obs := range byZone {
			for _, o := range obs {
				payload, err := base64.StdEncoding.DecodeString(o.Payload)
				if err != nil {
					return fmt.Errorf("observation payload not base64: %w", err)
				}
				conf := 0.9
				if err := (store.Observations{}).Insert(ctx, c, store.Observation{
					ID: uuid.New(), SubmissionID: subID, TaskID: taskID, ScanPointID: spID,
					ZoneID: zoneIDs[zt], Type: store.ObservationType(o.Type),
					Payload: payload, Confidence: &conf, ObservedAt: at,
				}, store.IngestAccepted); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}

	if err := correlate.New(db, quiet()).SweepOnce(ctx); err != nil {
		return nil, err
	}

	var out []findingOut
	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		rows, err := c.Query(ctx, `
			SELECT r.name, coalesce(f.instance_locator,''), f.status,
			       (SELECT count(*) FROM finding_exposure fe WHERE fe.finding_id = f.finding_id),
			       coalesce((a.primary_hostname), ''),
			       coalesce((SELECT host(ip_address) FROM asset_addresses aa
			                  WHERE aa.asset_id = f.asset_id AND aa.valid_to IS NULL LIMIT 1), ''),
			       -- The most-populated evidence row for this finding: the key count
			       -- of its richest evidence object. Zero means no evidence, or
			       -- evidence with an empty object — either way a finding an analyst
			       -- cannot verify by hand (ADR-006). corpus-check asserts this is > 0
			       -- for every finding.
			       coalesce((SELECT max((SELECT count(*)::int FROM jsonb_object_keys(e.data)))
			                   FROM evidence e
			                  WHERE e.tenant_id = f.tenant_id AND e.finding_id = f.finding_id
			                    AND jsonb_typeof(e.data) = 'object'), 0)
			  FROM findings f
			  JOIN rules r ON r.rule_id = f.rule_id
			  JOIN assets a ON a.asset_id = f.asset_id
			 WHERE f.tenant_id = $1`, tenant.UUID())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var fo findingOut
			var locator, hostname, addr string
			if err := rows.Scan(&fo.Rule, &locator, &fo.Status, &fo.Zones, &hostname, &addr, &fo.EvidenceKeys); err != nil {
				return err
			}
			fo.Address = addr
			if p, pr, ok := splitLocator(locator); ok {
				fo.Port = p
				_ = pr
			}
			out = append(out, fo)
		}
		return rows.Err()
	}); err != nil {
		return nil, err
	}
	return out, nil
}

func splitLocator(l string) (port int, proto string, ok bool) {
	i := strings.IndexByte(l, '/')
	if i < 0 {
		return 0, "", false
	}
	if _, err := fmt.Sscanf(l[:i], "%d", &port); err != nil {
		return 0, "", false
	}
	return port, l[i+1:], true
}

// runMerge replays one labelled merge scenario and returns the asset count.
func runMerge(ctx context.Context, db *store.DB, m mergeScenario) (int, error) {
	tenant, err := freshTenant(ctx, db, "corpus-merge")
	if err != nil {
		return 0, err
	}
	spID, subID, taskID, zoneIDs, err := seedScaffold(ctx, db, tenant, map[string][]obsIn{"internal": nil})
	if err != nil {
		return 0, err
	}
	zone := zoneIDs["internal"]
	c := correlate.New(db, quiet())

	// Each ADDRESS is its own sweep, so an address change between them is a
	// genuine second scan (a DHCP move), not one batch. Within a sweep, each key
	// the address holds is a SEPARATE service observation on its own port —
	// an SSH host key on 22 and a TLS cert on 443 are two independent moderate
	// keys and merge; the SSH key alone does not (ADR-007). Emitting both on one
	// observation would share a port and count as one key.
	base := time.Now().UTC().Add(-6 * time.Hour)
	for i, o := range m.Observations {
		at := base.Add(time.Duration(i) * time.Minute)
		var payloads [][]byte
		if o.SSHfp != "" {
			payloads = append(payloads, mustJSON(map[string]any{
				"address": o.Address, "port": 22, "protocol": "tcp", "service": "ssh",
				"method": "banner", "solicited": true, "safety_mode": "intrusive",
				"ssh": map[string]any{"host_key_type": "ssh-ed25519", "fingerprint": o.SSHfp},
			}))
		}
		if o.CertFP != "" {
			payloads = append(payloads, mustJSON(map[string]any{
				"address": o.Address, "port": 443, "protocol": "tcp", "service": "http",
				"method": "tls-probe", "solicited": true, "safety_mode": "intrusive",
				"tls": map[string]any{"version": "TLSv1.3",
					"chain": []any{map[string]any{"fingerprint": o.CertFP}}},
			}))
		}
		if err := db.Write(ctx, tenant, func(ctx context.Context, conn *store.Conn) error {
			for _, payload := range payloads {
				conf := 0.95
				if err := (store.Observations{}).Insert(ctx, conn, store.Observation{
					ID: uuid.New(), SubmissionID: subID, TaskID: taskID, ScanPointID: spID,
					ZoneID: zone, Type: store.ObsService, Payload: payload,
					Confidence: &conf, ObservedAt: at,
				}, store.IngestAccepted); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return 0, err
		}
		if err := c.SweepOnce(ctx); err != nil {
			return 0, err
		}
	}

	var n int
	if err := db.Read(ctx, tenant, func(ctx context.Context, conn *store.Conn) error {
		return conn.QueryRow(ctx, `SELECT count(*) FROM assets WHERE tenant_id = $1`,
			tenant.UUID()).Scan(&n)
	}); err != nil {
		return 0, err
	}
	return n, nil
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
