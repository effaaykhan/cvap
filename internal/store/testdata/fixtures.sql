-- One row per tenant in every tenant-scoped table, for two tenants.
--
-- Why this exists: rls_test.sql case 1 sweeps every tenant-scoped table and
-- asserts no foreign rows are visible. Against an empty table that assertion is
-- vacuous — it passed for 29 of 33 tables and proved nothing for any of them.
-- The suite reported that honestly rather than showing a green tick, which is
-- what made this worth fixing.
--
-- Loaded by rls_test.sql before the sweep. Runs as the migration role; the
-- assertions afterwards run as cvap_app.
--
-- Ordering is FK order. Where a table has a composite (tenant_id, parent_id) FK
-- the parent must exist in the SAME tenant, which is the constraint under test
-- and therefore also the thing that makes writing these fixtures fiddly.
--
-- Global knowledge tables (rule_packs, rules, vulnerability_defs,
-- rule_vuln_map, vendor_advisories, advisory_vuln_map, advisory_fixed_packages)
-- carry no tenant_id and are seeded once, not per tenant. findings needs a rule,
-- which is why they are here at all.

\set ON_ERROR_STOP on

-- ---------------------------------------------------------------------------
-- Global knowledge. One pack, one rule. No tenant_id by design (ADR-017).
-- ---------------------------------------------------------------------------

INSERT INTO rule_packs (name, version, signature, published_at)
VALUES ('fixture-pack', '1.0.0', 'ed25519:fixture-signature-not-real', now())
ON CONFLICT (name, version) DO NOTHING;

INSERT INTO rules (rule_pack_id, name, category, engine, execution_site,
                   default_severity, base_confidence, cwe, detection_logic)
SELECT rule_pack_id, 'fixture-rule', 'network', 'discovery', 'core',
       'medium', 0.800, 'CWE-1004', '{"kind":"fixture"}'::jsonb
  FROM rule_packs WHERE name = 'fixture-pack'
ON CONFLICT (rule_pack_id, name, version) DO NOTHING;

INSERT INTO vulnerability_defs (cve_id, title, cvss_base, in_kev)
VALUES ('CVE-1999-0000', 'fixture vulnerability', 5.0, false)
ON CONFLICT (cve_id) DO NOTHING;

INSERT INTO rule_vuln_map (rule_id, vuln_def_id, match_confidence)
SELECT r.rule_id, v.vuln_def_id, 0.500
  FROM rules r, vulnerability_defs v
 WHERE r.name = 'fixture-rule' AND v.cve_id = 'CVE-1999-0000'
ON CONFLICT (rule_id, vuln_def_id) DO NOTHING;

INSERT INTO vendor_advisories (advisory_ref, vendor, distro_release, severity, issued_at)
VALUES ('USN-0000-1', 'ubuntu', 'ubuntu2204', 'medium', now())
ON CONFLICT (advisory_ref) DO NOTHING;

INSERT INTO advisory_vuln_map (advisory_id, vuln_def_id)
SELECT a.advisory_id, v.vuln_def_id
  FROM vendor_advisories a, vulnerability_defs v
 WHERE a.advisory_ref = 'USN-0000-1' AND v.cve_id = 'CVE-1999-0000'
ON CONFLICT DO NOTHING;

INSERT INTO advisory_fixed_packages (advisory_id, distro_release, package_name, fixed_version, comparator)
SELECT advisory_id, 'ubuntu2204', 'openssl', '3.0.2-0ubuntu1.15', 'dpkg'
  FROM vendor_advisories WHERE advisory_ref = 'USN-0000-1'
ON CONFLICT (advisory_id, distro_release, package_name) DO NOTHING;

-- ---------------------------------------------------------------------------
-- Per-tenant rows, for both fixture tenants.
-- ---------------------------------------------------------------------------
-- A procedure rather than two copies: two copies drift, and a fixture set that
-- populates tenant A's table but not tenant B's makes the sweep pass for the
-- wrong reason — there would be no foreign rows to see.

CREATE OR REPLACE PROCEDURE fixture_seed_tenant(p_tenant uuid, p_tag text)
LANGUAGE plpgsql AS $proc$
DECLARE
    v_role      uuid;
    v_user      uuid;
    v_zone      uuid;
    v_point     uuid;
    v_policy    uuid;
    v_credprof  uuid;
    v_scan      uuid;
    v_target    uuid;
    v_job       uuid;
    v_task      uuid;
    v_asset     uuid;
    v_asset2    uuid;
    v_finding   uuid;
    v_rule      uuid;
    v_vuln      uuid;
    v_sub       text := 'fixture-submission-' || p_tag;
    v_obs       uuid := gen_random_uuid();
    v_kill      uuid;
BEGIN
    SELECT rule_id INTO v_rule FROM rules WHERE name = 'fixture-rule';
    SELECT vuln_def_id INTO v_vuln FROM vulnerability_defs WHERE cve_id = 'CVE-1999-0000';

    INSERT INTO roles (tenant_id, name) VALUES (p_tenant, 'fixture-role-' || p_tag)
        RETURNING role_id INTO v_role;

    INSERT INTO users (tenant_id, role_id, email, auth_provider, status)
        VALUES (p_tenant, v_role, 'fixture-' || p_tag || '@example.test', 'local', 'active')
        RETURNING user_id INTO v_user;

    INSERT INTO scan_zones (tenant_id, name, zone_type, trust_level, description)
        VALUES (p_tenant, 'fixture-zone-' || p_tag, 'internal', 50, 'fixture')
        RETURNING zone_id INTO v_zone;

    INSERT INTO network_ranges (tenant_id, zone_id, cidr, is_authorized)
        VALUES (p_tenant, v_zone, '192.0.2.0/24', true);

    INSERT INTO scan_points (tenant_id, zone_id, hostname, agent_version,
                             protocol_version, status, cert_fingerprint, last_heartbeat)
        VALUES (p_tenant, v_zone, 'fixture-sp-' || p_tag, '0.1.0', 'v1', 'online',
                'fixture-fp-' || p_tag, now())
        RETURNING scan_point_id INTO v_point;

    INSERT INTO scan_point_capabilities (tenant_id, scan_point_id, engine, engine_version)
        VALUES (p_tenant, v_point, 'discovery', '0.1.0');

    INSERT INTO scan_policies (tenant_id, name, safety_mode, max_rate_pps)
        VALUES (p_tenant, 'fixture-policy-' || p_tag, 'safe', 100)
        RETURNING policy_id INTO v_policy;

    INSERT INTO policy_scope_rules (tenant_id, policy_id, effect, match_type, match_value)
        VALUES (p_tenant, v_policy, 'allow', 'cidr', '192.0.2.0/24');

    INSERT INTO credential_profiles (tenant_id, name, cred_type, secret_ref)
        VALUES (p_tenant, 'fixture-cred-' || p_tag, 'ssh', 'vault://fixture/' || p_tag)
        RETURNING credential_profile_id INTO v_credprof;

    INSERT INTO scan_policy_credential_profiles (tenant_id, policy_id, credential_profile_id)
        VALUES (p_tenant, v_policy, v_credprof);

    INSERT INTO scans (tenant_id, policy_id, requested_by, scan_type, status)
        VALUES (p_tenant, v_policy, v_user, 'discovery', 'completed')
        RETURNING scan_id INTO v_scan;

    INSERT INTO scan_targets (tenant_id, scan_id, target_type, target_value,
                              authorization_verified, verified_at)
        VALUES (p_tenant, v_scan, 'cidr', '192.0.2.0/24', true, now())
        RETURNING target_id INTO v_target;

    INSERT INTO scan_jobs (tenant_id, scan_id, scan_point_id, engine, status, reassign_safe)
        VALUES (p_tenant, v_scan, v_point, 'discovery', 'completed', true)
        RETURNING job_id INTO v_job;

    INSERT INTO job_leases (tenant_id, job_id, epoch, holder_scan_point, state, expires_at)
        VALUES (p_tenant, v_job, 1, v_point, 'released', now() + interval '1 minute');

    INSERT INTO scan_tasks (tenant_id, job_id, target_id, task_target, status, progress_pct)
        VALUES (p_tenant, v_job, v_target, '192.0.2.5', 'completed', 100)
        RETURNING task_id INTO v_task;

    INSERT INTO credential_grants (tenant_id, credential_profile_id, job_id, cred_kind,
                                   target_scope, delivered_to_fingerprint, expires_at)
        VALUES (p_tenant, v_credprof, v_job, 'session_handle',
                '{"targets":["10.0.0.5"]}'::jsonb, 'fixture-fp-' || p_tag,
                now() + interval '10 minutes');

    -- Assets and everything derived onto them.
    INSERT INTO assets (tenant_id, primary_hostname, os_family, criticality, fragile)
        VALUES (p_tenant, 'fixture-host-' || p_tag, 'linux', 'medium', false)
        RETURNING asset_id INTO v_asset;

    INSERT INTO assets (tenant_id, primary_hostname, os_family, criticality, fragile)
        VALUES (p_tenant, 'fixture-host2-' || p_tag, 'linux', 'low', true)
        RETURNING asset_id INTO v_asset2;

    INSERT INTO asset_addresses (tenant_id, asset_id, ip_address, mac_address)
        VALUES (p_tenant, v_asset, '192.0.2.5', '02:00:00:00:00:01');

    INSERT INTO asset_identity_keys (tenant_id, asset_id, key_type, key_value, strength,
                                     merge_evidence_observation, merge_evidence_payload)
        VALUES (p_tenant, v_asset, 'ssh_hostkey', 'SHA256:fixture-' || p_tag, 2,
                v_obs, '{"copied_at_merge":true}'::jsonb);

    INSERT INTO services (tenant_id, asset_id, port, protocol, service_name, product, version, version_confidence)
        VALUES (p_tenant, v_asset, 22, 'tcp', 'ssh', 'OpenSSH', '8.9p1', 0.900);

    INSERT INTO software_components (tenant_id, asset_id, source, distro, package_name, installed_version)
        VALUES (p_tenant, v_asset, 'package_manager', 'ubuntu2204', 'openssl', '3.0.2-0ubuntu1.10');

    INSERT INTO asset_relationships (tenant_id, source_asset_id, target_asset_id,
                                     relationship_type, confidence)
        VALUES (p_tenant, v_asset, v_asset2, 'routes_to', 0.700);

    -- Result submission, then observations. One in each ingest_state, so the
    -- RLS sweep covers all three and the ingest_state filter has something to
    -- filter in every direction. pending is the state a row LANDS in and the one
    -- the finding pipeline must not see; a fixture set without it would let a
    -- read path that forgot its filter still look correct.
    INSERT INTO result_submissions (submission_id, tenant_id, job_id, lease_epoch,
                                    status, chunks_received, last_chunk_accepted, incomplete,
                                    termination_reason)
        VALUES (v_sub, p_tenant, v_job, 1, 'accepted', 1, 0, false, 'completed');

    INSERT INTO observations (observation_id, tenant_id, submission_id, task_id, scan_point_id,
                              zone_id, asset_id, observation_type, payload, confidence,
                              observed_at, ingest_state)
        VALUES (v_obs, p_tenant, v_sub, v_task, v_point, v_zone, v_asset,
                'host', '{"alive":true}'::jsonb, 0.950, now(), 'accepted');

    INSERT INTO observations (observation_id, tenant_id, submission_id, task_id, scan_point_id,
                              zone_id, asset_id, observation_type, payload, confidence,
                              observed_at, ingest_state)
        VALUES (gen_random_uuid(), p_tenant, v_sub, v_task, v_point, v_zone, NULL,
                'banner', '{"banner":"fixture"}'::jsonb, 0.500, now(), 'quarantined');

    -- Still pending: an upload that never sent its terminal chunk. Invisible to
    -- every accepted-filtered read, and what Observations.PendingOlderThan
    -- counts for the health surface.
    INSERT INTO observations (observation_id, tenant_id, submission_id, task_id, scan_point_id,
                              zone_id, asset_id, observation_type, payload, confidence,
                              observed_at, ingest_state)
        VALUES (gen_random_uuid(), p_tenant, v_sub, v_task, v_point, v_zone, NULL,
                'service', '{"port":22}'::jsonb, 0.250, now(), 'pending');

    -- Findings and everything hanging off them.
    INSERT INTO findings (tenant_id, asset_id, rule_id, vuln_def_id, source, dedup_key,
                          instance_locator, severity, confidence, status)
        VALUES (p_tenant, v_asset, v_rule, v_vuln, 'network',
                'fixture:' || p_tag || ':10.0.0.5:22:tcp', 'tcp/22', 'medium', 0.800, 'open')
        RETURNING finding_id INTO v_finding;

    INSERT INTO finding_exposure (tenant_id, finding_id, zone_id, internet_reachable, auth_required)
        VALUES (p_tenant, v_finding, v_zone, false, true);

    INSERT INTO finding_history (tenant_id, finding_id, from_status, to_status, changed_by, reason)
        VALUES (p_tenant, v_finding, NULL, 'open', v_user, 'fixture: created');

    INSERT INTO remediations (tenant_id, finding_id, description, assigned_to, status, due_at)
        VALUES (p_tenant, v_finding, 'fixture remediation', 'ops', 'proposed', now() + interval '7 days');

    INSERT INTO evidence (tenant_id, finding_id, observation_id, evidence_type, data,
                          object_store_ref, captured_at)
        VALUES (p_tenant, v_finding, v_obs, 'banner',
                '{"summary":"copied at finding creation, not referenced"}'::jsonb,
                's3://cvap-evidence/fixture/' || p_tag, now());

    INSERT INTO asset_resolution_queue (tenant_id, observation_id, observed_payload, key_type,
                                        key_value, candidate_asset_ids, conflict_reason)
        VALUES (p_tenant, v_obs, '{"copied_at_enqueue":true}'::jsonb, 'mac',
                '02:00:00:00:00:01', ARRAY[v_asset, v_asset2],
                'fixture: two candidates agree only on a weak key');

    -- Enrolment. One redeemed token, and the certificate the scan point holds.
    --
    -- token_hash is a digest of a value that never existed as a token: fixtures
    -- must not contain anything shaped like a working credential, even an
    -- expired one, because fixture files get copied into bug reports.
    INSERT INTO enrollment_tokens (tenant_id, zone_id, token_hash, issued_by,
                                   expires_at, redeemed_at, redeemed_scan_point,
                                   description)
        VALUES (p_tenant, v_zone, sha256(('fixture-not-a-real-token-' || p_tag)::bytea),
                v_user, now() + interval '1 day', now(), v_point,
                'fixture: already redeemed');

    -- A second, still pending, so the operator-queue read has something to find.
    INSERT INTO enrollment_tokens (tenant_id, zone_id, token_hash, issued_by,
                                   expires_at, description)
        VALUES (p_tenant, v_zone, sha256(('fixture-pending-' || p_tag)::bytea),
                v_user, now() + interval '1 day', 'fixture: pending');

    -- The certificate history. cert_fingerprint matches scan_points, which is
    -- the invariant the pairing statement exists to hold — a fixture that
    -- disagreed would encode the bug it is meant to help catch.
    INSERT INTO scan_point_certificates (tenant_id, scan_point_id, cert_fingerprint,
                                         serial_number, not_before, not_after)
        VALUES (p_tenant, v_point, 'fixture-fp-' || p_tag, 'fixture-serial-' || p_tag,
                now() - interval '1 day', now() + interval '89 days');

    -- Kill switch and one acknowledgement. Both tenant-scoped, so both must
    -- carry rows or case 1's sweep proves nothing for them (ADR-024).
    -- RESOLVED. A live kill in the fixtures is not a fixture, it is a fleet
    -- outage: Live() would return it on every reconnect and Jobs.Claim would
    -- refuse to assign anything for the life of any database loaded with these.
    INSERT INTO kill_switches (tenant_id, scope, issued_by, reason, resolved_at)
        VALUES (p_tenant, 'tenant', v_user, 'fixture: already resolved', now())
        RETURNING kill_id INTO v_kill;

    INSERT INTO kill_acks (tenant_id, kill_id, scan_point_id, tasks_halted)
        VALUES (p_tenant, v_kill, v_point, 2);

    -- One cancellation acknowledgement, for the same reason: cancel_acks is
    -- tenant-scoped, so case 1's sweep proves nothing for it while it is empty
    -- (ADR-024, migration 0025). The scan above is not cancelled and v_job is
    -- completed, which is deliberate — this row exists to be swept, not to
    -- describe a cancellation in flight. lease_epoch matches the job_leases row
    -- created above, because an ack naming an epoch that never existed would be
    -- a fixture teaching the wrong shape.
    INSERT INTO cancel_acks (tenant_id, job_id, scan_point_id, lease_epoch, tasks_halted)
        VALUES (p_tenant, v_job, v_point, 1, 0);

    INSERT INTO reports (tenant_id, report_type, parameters, object_store_ref, requested_by, generated_at)
        VALUES (p_tenant, 'exposure-summary', '{"window":"30d"}'::jsonb,
                's3://cvap-evidence/reports/fixture-' || p_tag, v_user, now());

    INSERT INTO audit_events (tenant_id, actor_id, actor_type, action, resource_type, resource_id, detail)
        VALUES (p_tenant, v_user, 'user', 'scan.start', 'scan', v_scan, '{"fixture":true}'::jsonb);

    -- The operator API's three tenant-scoped tables (migration 0026). Each
    -- needs a row or case 1's sweep proves nothing for it — which is how the
    -- sweep found them missing rather than a reviewer having to.

    INSERT INTO tenant_auth_config (tenant_id, method, oidc_issuer, oidc_client_id)
        VALUES (p_tenant, 'oidc', 'https://idp.invalid/', 'fixture-client-' || p_tag);

    -- A real argon2id verifier of no particular password. The CHECK requires the
    -- $argon2id$ prefix, and a fixture that satisfied it with a placeholder
    -- would teach the wrong shape to whoever copies this row.
    INSERT INTO user_credentials (tenant_id, user_id, password_hash)
        VALUES (p_tenant, v_user,
                '$argon2id$v=19$m=65536,t=3,p=1$' ||
                'ZmFrZXNhbHRmYWtlc2FsdA$' ||
                'ZmFrZWtleWZha2VrZXlmYWtla2V5ZmFrZWtleWZha2VrZXk');

    -- EXPIRED and revoked, and expiring within the 12-hour cap the CHECK
    -- enforces — a fixture that violated it would be a fixture teaching a
    -- session lifetime the schema forbids.
    -- EXPIRED and revoked. A live session in the fixtures is a working
    -- credential in every database loaded with them, and the token hash below is
    -- the SHA-256 of a known string — which is exactly why it must not
    -- authenticate anything. Same reasoning as the resolved kill switch above.
    INSERT INTO sessions (tenant_id, user_id, token_hash, csrf_hash,
                          issued_at, expires_at, revoked_at, revoked_reason)
        VALUES (p_tenant, v_user,
                sha256(('fixture-session-' || p_tag)::bytea),
                sha256(('fixture-csrf-' || p_tag)::bytea),
                now() - interval '2 days', now() - interval '2 days' + interval '1 hour',
                now() - interval '2 days', 'fixture: never valid');
END
$proc$;
