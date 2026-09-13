package dispatch_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
	"github.com/effaaykhan/cvap/internal/credsource"
	"github.com/effaaykhan/cvap/internal/hostkeytrust"
	"github.com/effaaykhan/cvap/internal/store"
)

// hostJobSeed controls what a credentialed-host job is seeded with.
type hostJobSeed struct {
	profile     bool   // authorise an ssh profile on the policy at all
	username    string // profile username ("" = none)
	knownHosts  string // operator-pinned lines ("" = none)
	observedKey string // an ssh_hostkey fingerprint on the asset at the target ("" = none)
	// seenOnce records observedKey with ONE sighting at the target: inventory,
	// not trust material (ADR-094). Default is two. Provenance is held constant
	// (new_asset) so the sighting count is the only thing that varies — it is
	// the count, not the verdict that recorded the key, that decides trust.
	seenOnce bool
	// secondKey seeds a SECOND distinct host key at the target with two
	// sightings on 22: the handover signature, which must refuse (ADR-094).
	// Since ADR-096 the schema itself makes that state unreachable on one
	// service — one live holder per address (0031), one live key per
	// (asset, type, port, protocol) (0045) — so the seed spells the second
	// key's service as 22/udp, the one row a pre-B45 build could have left
	// (B45): the fingerprint read is keyed on the sighting's PORT, and the
	// refusal is the defence that stays behind the index.
	secondKey    string
	secretRef    string
	target       string
	reassignSafe bool
}

const (
	seedTarget      = "192.0.2.7"
	seedFingerprint = "SHA256:EILUHN7jjJEOR+Csiwu2oipW3T5oL19wm6mFAlgCR8E"
)

// seedHostJob seeds a queued host job under a policy that authorises (or not)
// an ssh credential profile, and an asset at the target that has (or not) an
// observed host key. Returns the job id.
func seedHostJob(t *testing.T, db *store.DB, tenant store.TenantID, seed hostJobSeed) uuid.UUID {
	t.Helper()
	if seed.target == "" {
		seed.target = seedTarget
	}
	var jobID uuid.UUID
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
		var policyID, scanID, targetID uuid.UUID
		if err := c.QueryRow(ctx,
			`INSERT INTO scan_policies (tenant_id, name, max_rate_pps) VALUES ($1,$2,120) RETURNING policy_id`,
			tid, "p-"+uuid.NewString()[:8]).Scan(&policyID); err != nil {
			return err
		}
		if _, err := c.Exec(ctx,
			`INSERT INTO policy_scope_rules (tenant_id, policy_id, effect, match_type, match_value)
			 VALUES ($1,$2,'allow','cidr','192.0.2.0/24')`, tid, policyID); err != nil {
			return err
		}
		if seed.profile {
			var profileID uuid.UUID
			var user, known any
			if seed.username != "" {
				user = seed.username
			}
			if seed.knownHosts != "" {
				known = seed.knownHosts
			}
			if err := c.QueryRow(ctx,
				`INSERT INTO credential_profiles (tenant_id, name, cred_type, secret_ref, username, known_hosts)
				 VALUES ($1,$2,'ssh',$3,$4,$5) RETURNING credential_profile_id`,
				tid, "ssh-"+uuid.NewString()[:8], seed.secretRef, user, known).Scan(&profileID); err != nil {
				return err
			}
			if _, err := c.Exec(ctx,
				`INSERT INTO scan_policy_credential_profiles (tenant_id, policy_id, credential_profile_id)
				 VALUES ($1,$2,$3)`, tid, policyID, profileID); err != nil {
				return err
			}
		}
		if err := c.QueryRow(ctx,
			`INSERT INTO scans (tenant_id, policy_id, scan_type, status) VALUES ($1,$2,'host','running') RETURNING scan_id`,
			tid, policyID).Scan(&scanID); err != nil {
			return err
		}
		if err := c.QueryRow(ctx,
			`INSERT INTO scan_targets (tenant_id, scan_id, target_type, target_value, authorization_verified, verified_at)
			 VALUES ($1,$2,'cidr','192.0.2.0/24',true,now()) RETURNING target_id`,
			tid, scanID).Scan(&targetID); err != nil {
			return err
		}
		if err := c.QueryRow(ctx,
			`INSERT INTO scan_jobs (tenant_id, scan_id, engine, reassign_safe) VALUES ($1,$2,'host',$3) RETURNING job_id`,
			tid, scanID, seed.reassignSafe).Scan(&jobID); err != nil {
			return err
		}
		if _, err := c.Exec(ctx,
			`INSERT INTO scan_tasks (tenant_id, job_id, target_id, task_target) VALUES ($1,$2,$3,$4)`,
			tid, jobID, targetID, seed.target); err != nil {
			return err
		}
		if seed.observedKey != "" {
			var assetID uuid.UUID
			if err := c.QueryRow(ctx, `INSERT INTO assets (tenant_id) VALUES ($1) RETURNING asset_id`, tid).
				Scan(&assetID); err != nil {
				return err
			}
			if _, err := c.Exec(ctx,
				`INSERT INTO asset_addresses (tenant_id, asset_id, ip_address) VALUES ($1,$2,$3::inet)`,
				tid, assetID, seed.target); err != nil {
				return err
			}
			if _, err := c.Exec(ctx,
				`WITH k AS (
				   INSERT INTO asset_identity_keys (tenant_id, asset_id, key_type, key_value, strength, provenance,
				                                    merge_evidence_observation, merge_evidence_payload)
				   VALUES ($1,$2,'ssh_hostkey',$3,2,'new_asset',
				           gen_random_uuid(), '{"port":22,"protocol":"tcp"}'::jsonb)
				   RETURNING identity_key_id)
				 INSERT INTO asset_identity_key_sightings (tenant_id, identity_key_id, address, port, scans_seen, last_seen_scan, last_seen_at)
				 SELECT $1, identity_key_id, $5::inet, 22, CASE WHEN $4::bool THEN 1 ELSE 2 END, gen_random_uuid(), now() FROM k`,
				tid, assetID, seed.observedKey, seed.seenOnce, seed.target); err != nil {
				return err
			}
			if seed.secondKey != "" {
				if _, err := c.Exec(ctx,
					`WITH k AS (
					   INSERT INTO asset_identity_keys (tenant_id, asset_id, key_type, key_value, strength, provenance,
					                                    merge_evidence_observation, merge_evidence_payload)
					   VALUES ($1,$2,'ssh_hostkey',$3,2,'attach',gen_random_uuid(),'{"port":22,"protocol":"udp"}'::jsonb)
					   RETURNING identity_key_id)
					 INSERT INTO asset_identity_key_sightings (tenant_id, identity_key_id, address, port, scans_seen, last_seen_scan, last_seen_at)
					 SELECT $1, identity_key_id, $4::inet, 22, 2, gen_random_uuid(), now() FROM k`,
					tid, assetID, seed.secondKey, seed.target); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed host job: %v", err)
	}
	return jobID
}

// labKey writes an ed25519 private key under root and returns its file:// ref
// and the PEM bytes.
func labKey(t *testing.T, root string) (string, []byte) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	raw := pem.EncodeToMemory(block)
	path := filepath.Join(root, "lab.key")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return "file://" + path, raw
}

func fileResolver(t *testing.T, root string) credsource.Resolver {
	t.Helper()
	fr, err := credsource.NewFileResolver(root)
	if err != nil {
		t.Fatal(err)
	}
	return credsource.NewSchemeResolver(map[string]credsource.Resolver{"file": fr})
}

func hostHello(spID uuid.UUID) *scanpointv1.ScanPointMessage {
	return &scanpointv1.ScanPointMessage{
		Msg: &scanpointv1.ScanPointMessage_Hello{Hello: &scanpointv1.Hello{
			ScanPointId: spID.String(), ProtocolVersion: testVersion, AgentVersion: "0.1.0",
			Capabilities: []*scanpointv1.Capability{
				{Engine: "discovery", EngineVersion: "0.1.0", Enabled: true},
				{Engine: "host", EngineVersion: "0.1.0", Enabled: true},
			},
		}},
	}
}

func auditActions(t *testing.T, db *store.DB, tenant store.TenantID, jobID uuid.UUID) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		events, err := (store.AuditEvents{}).ListByResource(ctx, c, "scan_job", jobID, 50)
		if err != nil {
			return err
		}
		for _, e := range events {
			out[e.Action] = e.Detail
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// ============================================================================
// The wire: a host job travels with cred_user and known_hosts on the assignment
// and its secret on the grant that follows, Core records the release and the
// trust-source claim, erases its own copy once the bytes are on the wire, and
// closes the grant record on the runtime's attestation.
// ============================================================================
func TestHostJobTravelsWithItsGrantAndCoreErasesItsCopy(t *testing.T) {
	db := testDB(t)
	svc := newService(t, db)
	root := t.TempDir()
	ref, keyPEM := labKey(t, root)
	svc.UseSecretResolver(fileResolver(t, root))
	tenant, leaf, spID := enrolledScanPoint(t, db)
	jobID := seedHostJob(t, db, tenant, hostJobSeed{
		profile: true, username: "lab", observedKey: seedFingerprint, secretRef: ref,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fs := newFakeStream(peerCtx(ctx, leaf))
	done := make(chan error, 1)
	go func() { done <- svc.Connect(fs) }()
	fs.push(hostHello(spID))

	assign := fs.waitFor(t, "JobAssignment", func(m *scanpointv1.CoreMessage) bool {
		return m.GetJob() != nil
	}).GetJob()
	if assign.GetJobId() != jobID.String() || assign.GetEngine() != "host" {
		t.Fatalf("assignment = %s/%s, want the host job %s", assign.GetJobId(), assign.GetEngine(), jobID)
	}
	if assign.GetCredUser() != "lab" {
		t.Errorf("cred_user = %q, want lab", assign.GetCredUser())
	}
	src, material, err := hostkeytrust.Parse(assign.GetKnownHosts())
	if err != nil {
		t.Fatalf("known_hosts on the wire does not parse: %v (%q)", err, assign.GetKnownHosts())
	}
	if src != hostkeytrust.SourceObserved {
		t.Errorf("trust source = %q, want observed (no operator pin on this profile)", src)
	}
	if !strings.Contains(material, seedTarget+" "+seedFingerprint) {
		t.Errorf("known_hosts material %q lacks the observed fingerprint for %s", material, seedTarget)
	}

	grantMsg := fs.waitFor(t, "CredentialGrant", func(m *scanpointv1.CoreMessage) bool {
		return m.GetCredential() != nil
	})
	grant := grantMsg.GetCredential()
	if grant.GetJobId() != jobID.String() {
		t.Fatalf("grant for job %s, want %s", grant.GetJobId(), jobID)
	}
	if grant.GetCredKind() != scanpointv1.CredKind_RAW_SECRET {
		t.Errorf("cred_kind = %v, want RAW_SECRET", grant.GetCredKind())
	}
	fs.mu.Lock()
	sentMaterial := append([]byte(nil), fs.grantMaterial...)
	fs.mu.Unlock()
	if string(sentMaterial) != string(keyPEM) {
		t.Errorf("the material that crossed the wire is not the resolved key (%d bytes vs %d)", len(sentMaterial), len(keyPEM))
	}
	// Core's copy: erased the moment Send returned. The message object the fake
	// stream retained is the one the send loop erased.
	waitUntil(t, "grant material erased after send", func() bool {
		return len(grant.GetMaterial()) == 0
	})

	// The release record and the claim.
	var grantID uuid.UUID
	var zeroisedAt *time.Time
	var fingerprint string
	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx,
			`SELECT grant_id, zeroised_at, delivered_to_fingerprint FROM credential_grants WHERE job_id = $1`, jobID).
			Scan(&grantID, &zeroisedAt, &fingerprint)
	}); err != nil {
		t.Fatalf("credential_grants row: %v", err)
	}
	if grantID.String() != grant.GetGrantId() {
		t.Errorf("grant_id on the wire %s != recorded %s", grant.GetGrantId(), grantID)
	}
	if zeroisedAt != nil {
		t.Error("zeroised_at set before any attestation arrived")
	}
	if fingerprint == "" {
		t.Error("delivered_to_fingerprint is empty; the recipient of a secret must be recorded")
	}
	events := auditActions(t, db, tenant, jobID)
	granted, ok := events["credential.granted"]
	if !ok {
		t.Fatal("no credential.granted audit event")
	}
	if granted["trust_source"] != "observed" {
		t.Errorf("audit trust_source = %v, want observed — the audit must record the same claim the wire carries", granted["trust_source"])
	}
	if granted["cred_user"] != "lab" || granted["grant_id"] != grantID.String() {
		t.Errorf("audit detail incomplete: %v", granted)
	}
	for k, v := range granted {
		if s, isStr := v.(string); isStr && (strings.Contains(s, "PRIVATE KEY") || strings.Contains(s, ref)) {
			t.Errorf("audit detail %s leaks the secret or its ref: %q", k, s)
		}
	}

	// Only the recipient can close the record: a same-tenant scan point that
	// never received the grant cannot mark it zeroised by naming the job.
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.CredentialGrants{}).MarkZeroised(ctx, c, jobID, "sha256:some-other-scan-point", time.Now())
	}); err != nil {
		t.Fatal(err)
	}
	var strayClose *time.Time
	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx, `SELECT zeroised_at FROM credential_grants WHERE grant_id = $1`, grantID).Scan(&strayClose)
	}); err != nil {
		t.Fatal(err)
	}
	if strayClose != nil {
		t.Fatal("a scan point that never received the grant closed its record")
	}

	// The runtime attests; the record closes.
	fs.push(&scanpointv1.ScanPointMessage{Msg: &scanpointv1.ScanPointMessage_Terminal{Terminal: &scanpointv1.JobTerminal{
		JobId: jobID.String(), LeaseEpoch: assign.GetLeaseEpoch(),
		Reason: scanpointv1.TerminationReason_COMPLETED, CredentialsZeroised: true,
	}}})
	waitUntil(t, "zeroised_at set on attestation", func() bool {
		var at *time.Time
		_ = db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
			return c.QueryRow(ctx, `SELECT zeroised_at FROM credential_grants WHERE grant_id = $1`, grantID).Scan(&at)
		})
		return at != nil
	})

	fs.closeInbound()
	cancel()
	<-done
}

// An operator-pinned known_hosts on the profile wins over the observed key, and
// the wire says so.
func TestOperatorPinnedKnownHostsOutranksTheObservedKey(t *testing.T) {
	db := testDB(t)
	svc := newService(t, db)
	root := t.TempDir()
	ref, _ := labKey(t, root)
	svc.UseSecretResolver(fileResolver(t, root))
	tenant, leaf, spID := enrolledScanPoint(t, db)
	// The pin also names an unrelated host; that line must NOT travel — trust
	// is per task, and a pin for one host is not trust for another.
	pinned := "10.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBjx8vfRme9HSuAOm1/KN4LFQIKzNY9OBoETspqHOxwx unrelated\n" +
		seedTarget + " ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDDUmMQDAdEk6rgAH3kUPUOd/R8OWzmryZHI+kQWr8MG pinned\n"
	jobID := seedHostJob(t, db, tenant, hostJobSeed{
		profile: true, username: "lab", knownHosts: pinned, observedKey: seedFingerprint, secretRef: ref,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fs := newFakeStream(peerCtx(ctx, leaf))
	done := make(chan error, 1)
	go func() { done <- svc.Connect(fs) }()
	fs.push(hostHello(spID))
	assign := fs.waitFor(t, "JobAssignment", func(m *scanpointv1.CoreMessage) bool {
		return m.GetJob() != nil
	}).GetJob()
	src, material, err := hostkeytrust.Parse(assign.GetKnownHosts())
	if err != nil {
		t.Fatal(err)
	}
	if src != hostkeytrust.SourceOperator || !strings.Contains(material, "pinned") {
		t.Errorf("known_hosts = %q/%q, want the operator pin", src, material)
	}
	if strings.Contains(material, seedFingerprint) {
		t.Error("the observed fingerprint travelled alongside the operator pin; the pin is the trust root, not an addition to it")
	}
	if strings.Contains(material, "unrelated") {
		t.Error("a pin line for a host outside the job travelled with it; trust material is per task")
	}
	if events := auditActions(t, db, tenant, jobID); events["credential.granted"]["trust_source"] != "operator" {
		t.Errorf("audit trust_source = %v, want operator", events["credential.granted"]["trust_source"])
	}
	fs.closeInbound()
	cancel()
	<-done
}

// ============================================================================
// Refusals, before the secret is touched: no profile, no username, no trust
// material from either source (the TOFU shape), no resolver at all.
// ============================================================================
func TestHostJobIsRefusedRatherThanDispatchedUncredentialed(t *testing.T) {
	for _, tc := range []struct {
		name     string
		seed     hostJobSeed
		resolver bool
		want     string
	}{
		{"no ssh profile authorised", hostJobSeed{profile: false, observedKey: seedFingerprint}, true, "authorises no ssh credential profile"},
		{"profile without a username", hostJobSeed{profile: true, observedKey: seedFingerprint}, true, "has no username"},
		{"no observed key and no operator pin", hostJobSeed{profile: true, username: "lab"}, true, "trust-on-first-use is not permitted"},
		// ADR-094: a key is trust material at an address only once two distinct
		// scans have seen it there. One sighting is trust-on-first-use by another
		// name, and the refusal is the same one — from Core's side there is no
		// observed key.
		// ADR-094: two distinct host keys both qualifying at one address and port
		// is the handover signature; whichever machine answers would be accepted.
		// Reachable only through a legacy protocol spelling since ADR-096 — see
		// hostJobSeed.secondKey and TestTwoLiveKeysOnOneServiceAreUnreachable.
		{"two host keys qualify at the target", hostJobSeed{profile: true, username: "lab", observedKey: seedFingerprint,
			secondKey: "SHA256:" + strings.Repeat("B", 43)}, true, "distinct ssh host keys qualify"},
		{"key seen once at the target", hostJobSeed{profile: true, username: "lab", observedKey: seedFingerprint, seenOnce: true}, true, "trust-on-first-use is not permitted"},
		{"no secret resolver configured", hostJobSeed{profile: true, username: "lab", observedKey: seedFingerprint}, false, "no secret resolver configured"},
		{"operator pin does not cover the target", hostJobSeed{profile: true, username: "lab", observedKey: seedFingerprint,
			knownHosts: "10.0.0.1 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBjx8vfRme9HSuAOm1/KN4LFQIKzNY9OBoETspqHOxwx other\n"}, true, "has no line for task"},
		// A stored fingerprint with an embedded newline passed a prefix check
		// and composed a trust line for ANOTHER host (security review).
		{"observed key with an injected line", hostJobSeed{profile: true, username: "lab",
			observedKey: seedFingerprint + "\n10.9.9.9 SHA256:ATTACKERKEYFINGERPRINTxxxxxxxxxxxxxxxxxxxx"}, true, "not a well-formed SHA256 fingerprint"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testDB(t)
			svc := newService(t, db)
			root := t.TempDir()
			ref, _ := labKey(t, root)
			if tc.resolver {
				svc.UseSecretResolver(fileResolver(t, root))
			}
			tenant, leaf, spID := enrolledScanPoint(t, db)
			tc.seed.secretRef = ref
			jobID := seedHostJob(t, db, tenant, tc.seed)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fs := newFakeStream(peerCtx(ctx, leaf))
			done := make(chan error, 1)
			go func() { done <- svc.Connect(fs) }()
			fs.push(hostHello(spID))

			var refused map[string]any
			waitUntil(t, "job.credential_refused audit event", func() bool {
				refused = auditActions(t, db, tenant, jobID)["job.credential_refused"]
				return refused != nil
			})
			if why, _ := refused["reason"].(string); !strings.Contains(why, tc.want) {
				t.Errorf("refusal reason %q does not say %q", why, tc.want)
			}
			var status string
			if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
				return c.QueryRow(ctx, `SELECT status FROM scan_jobs WHERE job_id = $1`, jobID).Scan(&status)
			}); err != nil {
				t.Fatal(err)
			}
			if status != "failed" {
				t.Errorf("job status = %q, want failed: a refused job must not stay claimable", status)
			}
			fs.mu.Lock()
			for _, m := range fs.outbound {
				if m.GetJob() != nil || m.GetCredential() != nil {
					t.Errorf("a refused host job reached the wire: %T", m.GetMsg())
				}
			}
			fs.mu.Unlock()
			var grants int
			_ = db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
				return c.QueryRow(ctx, `SELECT count(*) FROM credential_grants WHERE job_id = $1`, jobID).Scan(&grants)
			})
			if grants != 0 {
				t.Errorf("%d credential_grants row(s) for a refused job", grants)
			}
			fs.closeInbound()
			cancel()
			<-done
		})
	}
}

// ============================================================================
// The resolve-then-abort window (ADR-091): a secret resolved and then not sent
// must be erased on that path too. Two doors: the transaction rolling back after
// Resolve, and the outbound queue refusing the assignment.
// ============================================================================

// trackingResolver hands out material it keeps a reference to, so a test can
// check the bytes afterwards regardless of what the producer did with its own
// pointer. onResolve runs inside Resolve, before returning.
type trackingResolver struct {
	material  []byte
	handed    [][]byte
	onResolve func()
}

func (r *trackingResolver) Resolve(context.Context, string) ([]byte, error) {
	b := append([]byte(nil), r.material...)
	r.handed = append(r.handed, b)
	if r.onResolve != nil {
		r.onResolve()
	}
	return b, nil
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func TestResolvedMaterialIsErasedWhenTheSendIsRefused(t *testing.T) {
	db := testDB(t)
	svc := newService(t, db)
	tenant, _, spID := enrolledScanPoint(t, db)
	declareHost(t, db, tenant, spID)
	jobID := seedHostJob(t, db, tenant, hostJobSeed{
		profile: true, username: "lab", observedKey: seedFingerprint, secretRef: "file:///unused",
	})
	tr := &trackingResolver{material: []byte("-----BEGIN OPENSSH PRIVATE KEY----- not really")}
	svc.UseSecretResolver(tr)

	// An unbuffered channel nobody reads: every trySend is refused. The job is
	// claimed and leased regardless — the sweeper's business, as for any
	// dropped assignment — but the secret must not survive the drop.
	out := make(chan *scanpointv1.CoreMessage)
	svc.OfferWorkForTest(context.Background(), tenant, spID, "sha256:test", out, 5)

	if len(tr.handed) != 1 {
		t.Fatalf("resolver called %d times, want 1", len(tr.handed))
	}
	if !allZero(tr.handed[0]) {
		t.Fatal("the resolved secret survived a refused send: Core holds material it will never deliver")
	}
	// The grant row and audit event were written in the transaction, which is
	// correct — the release was decided — and the drop is logged by offerWork.
	if events := auditActions(t, db, tenant, jobID); events["credential.granted"] == nil {
		t.Error("no credential.granted event for a grant that was issued (and then dropped)")
	}
}

func TestResolvedMaterialIsErasedWhenTheTransactionRollsBack(t *testing.T) {
	db := testDB(t)
	svc := newService(t, db)
	tenant, _, spID := enrolledScanPoint(t, db)
	declareHost(t, db, tenant, spID)
	jobID := seedHostJob(t, db, tenant, hostJobSeed{
		profile: true, username: "lab", observedKey: seedFingerprint, secretRef: "file:///unused",
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// The resolver is the LAST refusable step before the grant row; cancelling
	// the pass's context from inside it makes the very next statement fail,
	// which rolls the claim back after the secret exists in memory.
	tr := &trackingResolver{material: []byte("-----BEGIN OPENSSH PRIVATE KEY----- not really"), onResolve: cancel}
	svc.UseSecretResolver(tr)

	out := make(chan *scanpointv1.CoreMessage, 8)
	svc.OfferWorkForTest(ctx, tenant, spID, "sha256:test", out, 5)

	if len(tr.handed) != 1 {
		t.Fatalf("resolver called %d times, want 1", len(tr.handed))
	}
	if !allZero(tr.handed[0]) {
		t.Fatal("the resolved secret survived a rolled-back pass")
	}
	select {
	case m := <-out:
		t.Fatalf("something reached the wire from a rolled-back pass: %T", m.GetMsg())
	default:
	}
	var status string
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx, `SELECT status FROM scan_jobs WHERE job_id = $1`, jobID).Scan(&status)
	}); err != nil {
		t.Fatal(err)
	}
	if status != "queued" {
		t.Errorf("job status = %q after a rolled-back pass, want queued", status)
	}
}

func declareHost(t *testing.T, db *store.DB, tenant store.TenantID, spID uuid.UUID) {
	t.Helper()
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := (store.ScanPoints{}).DeclareCapability(ctx, c, spID, store.EngineHost, "0.1.0", true)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// The state "two distinct host keys qualify at one address on one service" is
// unreachable by construction since ADR-096: migration 0045's one-live-key
// index refuses the second key. The dispatch refusal above it is defence in
// depth, and this is the test that says which layer carries the property —
// the seed this suite used before 0045 is exactly what is refused here.
func TestTwoLiveKeysOnOneServiceAreUnreachable(t *testing.T) {
	db := testDB(t)
	tenant, _, _ := enrolledScanPoint(t, db)
	ctx := context.Background()
	err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
		var assetID uuid.UUID
		if err := c.QueryRow(ctx, `INSERT INTO assets (tenant_id) VALUES ($1) RETURNING asset_id`, tid).Scan(&assetID); err != nil {
			return err
		}
		for _, fp := range []string{seedFingerprint, "SHA256:" + strings.Repeat("B", 43)} {
			if _, err := c.Exec(ctx, `INSERT INTO asset_identity_keys (tenant_id, asset_id, key_type, key_value, strength, provenance,
			                                    merge_evidence_observation, merge_evidence_payload)
			   VALUES ($1,$2,'ssh_hostkey',$3,2,'attach',gen_random_uuid(),'{"port":22,"protocol":"tcp"}'::jsonb)`,
				tid, assetID, fp); err != nil {
				return err
			}
		}
		return nil
	})
	if !errors.Is(err, store.ErrConflict) {
		t.Fatalf("a second live key on one (asset, type, port, protocol): err=%v; want the one-live-key index to refuse it", err)
	}
}
