-- 0032_builtin_rule_pack
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Run schema-auditor before merging.
--
-- rule_packs and rules are GLOBAL knowledge tables — no tenant_id, no RLS
-- (ADR-009). They are correct to have none: a rule is the same detection logic
-- for every tenant.

-- The built-in rule pack, and week 6's non-CVE rules.
--
-- ============================================================================
-- Seeded by a MIGRATION, not by Core at runtime, because the app role cannot
-- write here — and that is the point rather than an obstacle.
-- ============================================================================
--
-- `rules` is granted SELECT-only to cvap_app (migration 0010): knowledge data is
-- signed and imported out-of-band (ADR-019), never written by the application.
-- The built-in pack is content that ships WITH THE BUILD, so the writer that
-- ships with the build — the migration set — is the one that seeds it. This is
-- the same split BuiltinCorpus draws for fingerprints: the in-build half is
-- trusted by provenance, the imported half by an ed25519 signature. Signed
-- import writes these same rows through a verified path, and its unblocker is
-- the signing-key custody named in ADR-048.
--
-- # detection_logic is {evaluator, params}
--
-- The evaluator name is CODE (internal/rules, a closed vocabulary amendment-
-- gated like probe kinds, ADR-049); the params are CONTENT a pack may tune. A
-- rule naming an evaluator this build does not implement is REFUSED at load, not
-- skipped — internal/rules.Load — because a rule that silently never fires is the
-- failure a rule engine exists to prevent.
--
-- # execution_site is 'core' for every rule here
--
-- All evidence-based (ADR-013): each reads a certificate, a host key, a banner or
-- a header session 13 already gathered. None is request-coupled, so a rule
-- correction is a re-evaluation over stored observations rather than a fleet
-- rollout.

BEGIN;

INSERT INTO rule_packs (rule_pack_id, name, version, signature, published_at)
VALUES (
    '00000000-0000-0000-0000-0000000000c6',
    'cvap-builtin',
    '2026.09.6',
    -- Not an ed25519 signature, and deliberately not faking one. A built-in
    -- pack is trusted because it shipped in the migration set — the same trust
    -- root as the schema itself — not because it carries a detached signature.
    -- ADR-019's signature requirement is for packs that arrive over the wire or
    -- by offline import; this sentinel says which kind this is, so nothing later
    -- reads it as a verified external signature.
    'builtin:trusted-by-provenance',
    '2026-09-06T00:00:00Z'
);
-- No ON CONFLICT guard, and that is deliberate after a schema audit: the 13 rule
-- inserts below have no equivalent guard (they would violate
-- rules_pack_name_version_key on a replay), so a DO NOTHING here would only make
-- the first statement LOOK idempotent while the next one hard-failed. Migrations
-- run once; migrate-verify's up/down/up runs each up against a freshly recreated
-- schema. Honest non-idempotency beats a guard that covers one row of thirteen.

-- Helper: every rule here belongs to the built-in pack, runs at Core, and is a
-- rules-engine rule. Written out per row rather than hidden in a function so the
-- seed reads as data.
INSERT INTO rules (
    rule_pack_id, name, category, engine, execution_site,
    default_severity, base_confidence, cwe, detection_logic, evidence_requirements,
    remediation_template
) VALUES

-- ---- certificates: direct observation of the condition, high confidence ----

('00000000-0000-0000-0000-0000000000c6',
 'tls-certificate-expired', 'tls', 'rules', 'core',
 'high', 0.990, 'CWE-298',
 '{"evaluator": "tls.expired", "params": {}}',
 '{"needs": ["service.tls.chain[0].not_after"]}',
 'Reissue the certificate. It expired and clients that verify it are failing closed or being trained to click through warnings.'),

('00000000-0000-0000-0000-0000000000c6',
 'tls-certificate-expiring-soon', 'tls', 'rules', 'core',
 'medium', 0.990, 'CWE-298',
 '{"evaluator": "tls.expiring", "params": {"warn_days": 30}}',
 '{"needs": ["service.tls.chain[0].not_after"]}',
 'Renew the certificate before it expires. Automate renewal if this is recurring.'),

('00000000-0000-0000-0000-0000000000c6',
 'tls-self-signed-non-dev', 'tls', 'rules', 'core',
 'medium', 0.950, 'CWE-295',
 '{"evaluator": "tls.self_signed", "params": {"exempt_environments": ["dev", "development", "test", "staging", "lab"]}}',
 '{"needs": ["service.tls.chain[0].self_signed", "asset.environment"]}',
 'Replace with a certificate from a trusted CA. Self-signed certificates train users to bypass trust warnings.'),

('00000000-0000-0000-0000-0000000000c6',
 'tls-missing-chain', 'tls', 'rules', 'core',
 'low', 0.950, 'CWE-295',
 '{"evaluator": "tls.missing_chain", "params": {}}',
 '{"needs": ["service.tls.chain_length", "service.tls.chain[0].self_signed"]}',
 'Configure the server to present the intermediate certificate chain. Clients without the intermediate cached will fail to verify.'),

('00000000-0000-0000-0000-0000000000c6',
 'tls-weak-key', 'tls', 'rules', 'core',
 'high', 0.990, 'CWE-326',
 '{"evaluator": "tls.weak_key", "params": {"min_rsa_bits": 2048}}',
 '{"needs": ["service.tls.chain[0].public_key_algorithm", "service.tls.chain[0].key_bits"]}',
 'Reissue with at least a 2048-bit RSA key or an elliptic-curve key.'),

('00000000-0000-0000-0000-0000000000c6',
 'tls-legacy-version-negotiated', 'tls', 'rules', 'core',
 'medium', 0.950, 'CWE-327',
 '{"evaluator": "tls.legacy_negotiated", "params": {}}',
 '{"needs": ["service.tls.version"]}',
 'Disable TLS 1.0 and 1.1. The server negotiated a legacy version against a modern client, so it offers nothing better on this port.'),

('00000000-0000-0000-0000-0000000000c6',
 'tls-weak-cipher-negotiated', 'tls', 'rules', 'core',
 'medium', 0.950, 'CWE-327',
 '{"evaluator": "tls.weak_cipher_negotiated", "params": {}}',
 '{"needs": ["service.tls.cipher_suite"]}',
 'Disable the negotiated cipher suite. It is classed insecure by the TLS stack, so it is the best this server offered a modern client.'),

-- ---- plaintext protocols: one evaluator, a row per protocol ----

('00000000-0000-0000-0000-0000000000c6',
 'plaintext-telnet', 'exposure', 'rules', 'core',
 'high', 0.950, 'CWE-319',
 '{"evaluator": "plaintext.service", "params": {"services": ["telnet"]}}',
 '{"needs": ["service.service", "service.tls"]}',
 'Replace Telnet with SSH. Credentials and session content cross the network in cleartext.'),

('00000000-0000-0000-0000-0000000000c6',
 'plaintext-ftp', 'exposure', 'rules', 'core',
 'medium', 0.950, 'CWE-319',
 '{"evaluator": "plaintext.service", "params": {"services": ["ftp"]}}',
 '{"needs": ["service.service", "service.tls"]}',
 'Replace FTP with SFTP or FTPS. Credentials cross the network in cleartext.'),

-- ---- HTTP: read from the sanitised evidence excerpt (see the evaluator) ----

('00000000-0000-0000-0000-0000000000c6',
 'http-no-https-redirect', 'web', 'rules', 'core',
 'low', 0.750, 'CWE-319',
 '{"evaluator": "http.no_https_redirect", "params": {}}',
 '{"needs": ["service.evidence (HTTP status line and Location header)"]}',
 'Redirect plain HTTP to HTTPS with a 301, and serve HSTS on the HTTPS listener.'),

('00000000-0000-0000-0000-0000000000c6',
 'http-missing-security-headers', 'web', 'rules', 'core',
 'low', 0.750, 'CWE-693',
 '{"evaluator": "http.missing_headers", "params": {"required": ["Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options"]}}',
 '{"needs": ["service.evidence (HTTP response headers)"]}',
 'Set the missing response headers. They are defence-in-depth against transport downgrade, injection and MIME confusion.'),

-- ---- exposure ----

('00000000-0000-0000-0000-0000000000c6',
 'management-interface-untrusted-zone', 'exposure', 'rules', 'core',
 'high', 0.900, 'CWE-284',
 '{"evaluator": "exposure.management_untrusted", "params": {"ports": [22, 3389, 5985, 5986, 3306, 5432, 1433, 27017, 6379], "zone_types": ["external", "dmz"]}}',
 '{"needs": ["service.port", "observation.zone"]}',
 'Restrict the management port to a trusted network or a VPN. It was observed reachable from an untrusted vantage point.'),

-- ---- SSH ----

('00000000-0000-0000-0000-0000000000c6',
 'ssh-weak-algorithms', 'crypto', 'rules', 'core',
 'low', 0.900, 'CWE-327',
 '{"evaluator": "ssh.weak_algorithms", "params": {"host_key": ["ssh-dss", "ssh-rsa"], "kex": ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"]}}',
 '{"needs": ["service.ssh.host_key_algorithms", "service.ssh.kex_algorithms"]}',
 'Disable the SHA-1 and legacy algorithms in sshd_config. Modern clients no longer offer them and their presence signals an outdated configuration.')
;

COMMIT;
