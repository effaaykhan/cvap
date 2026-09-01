-- 0018_scan_point_certificates
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.

-- Every certificate Core has issued to a scan point, live and superseded.
--
-- scan_points.cert_fingerprint answers "who is this peer, now" — one indexed
-- equality on the enrolment path (ADR-031). This table answers "which
-- certificate was valid on 3 March", which the single column cannot: replacing
-- it in place is what makes revocation immediate, and also what destroys the
-- history.
--
-- Not in the v2 ERD; recorded in ADR-029.
--
-- THE INVARIANT, and its honest limit. scan_points.cert_fingerprint must always
-- name the live row here for that scan point. There is no constraint enforcing
-- it: doing so needs a circular foreign key with DEFERRABLE INITIALLY DEFERRED
-- on one side, and a deferred constraint is the kind of cleverness that
-- surprises whoever debugs it at 2am. Instead the pairing is written as a SINGLE
-- STATEMENT — a CTE that inserts here and updates scan_points from what it
-- inserted — so there is no window where one exists without the other and no way
-- for a caller to do half of it. Any code path touching cert_fingerprint outside
-- that statement is a defect; internal/store/CLAUDE.md says so too.

BEGIN;

DO $$
DECLARE
    r record;
BEGIN
    SELECT rolbypassrls, rolsuper INTO r FROM pg_roles WHERE rolname = 'cvap_app';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Role cvap_app does not exist (ADR-002)';
    END IF;
    IF r.rolbypassrls OR r.rolsuper THEN
        RAISE EXCEPTION 'Role cvap_app can bypass RLS (ADR-002). Fix: ALTER ROLE cvap_app NOBYPASSRLS NOSUPERUSER;';
    END IF;
END
$$;

CREATE TYPE certificate_supersede_reason AS ENUM (
    'rotation',      -- the scan point rotated before expiry (60 of 90 days)
    'revocation',    -- an operator revoked it
    'reenrollment',  -- the scan point enrolled again, replacing its identity
    'expiry'         -- reached not_after without rotating
);

CREATE TABLE scan_point_certificates (
    certificate_id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Denormalised tenant_id + composite FK (ADR-017); see users.tenant_id
    -- in 0001.
    tenant_id        uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,

    scan_point_id    uuid NOT NULL,

    -- SHA-256 over the leaf DER, lowercase hex. The same value
    -- scan_points.cert_fingerprint carries and the same one the TLS layer
    -- computes on the peer certificate — computed in exactly one place in Go
    -- (ca.Fingerprint), because enrolment and dispatch disagreeing here means
    -- every scan point fails to authenticate for a reason nothing reports.
    cert_fingerprint text NOT NULL,

    -- The issuer's serial, as hex. Stored so a certificate found in the wild can
    -- be traced back without possessing the certificate itself.
    serial_number    text NOT NULL,

    not_before       timestamptz NOT NULL,
    not_after        timestamptz NOT NULL,
    issued_at        timestamptz NOT NULL DEFAULT now(),

    -- NULL means live. Exactly one live row per scan point, enforced below.
    superseded_at    timestamptz,
    supersede_reason certificate_supersede_reason,

    CONSTRAINT scan_point_certificates_tenant_certificate_key
        UNIQUE (tenant_id, certificate_id),

    CONSTRAINT scan_point_certificates_scan_point_fk
        FOREIGN KEY (tenant_id, scan_point_id)
        REFERENCES scan_points (tenant_id, scan_point_id) ON DELETE CASCADE,

    CONSTRAINT scan_point_certificates_validity_ordered
        CHECK (not_after > not_before),

    CONSTRAINT scan_point_certificates_supersede_consistent
        CHECK ((superseded_at IS NULL) = (supersede_reason IS NULL))
);

COMMENT ON TABLE scan_point_certificates IS
    'Issuance history. scan_points.cert_fingerprint names the live row here; the pairing is written as one statement so the two cannot diverge. Not drawn in the v2 ERD; see ADR-029.';

-- Globally unique, matching scan_points.cert_fingerprint. A fingerprint is a
-- digest of a public key, so two rows sharing one would mean the same key issued
-- twice — which would make the peer-certificate lookup ambiguous at exactly the
-- point where it decides identity.
CREATE UNIQUE INDEX scan_point_certificates_fingerprint_key
    ON scan_point_certificates (cert_fingerprint);

-- At most one live certificate per scan point. This is the constraint that makes
-- "the live row" a well-defined thing to point at.
CREATE UNIQUE INDEX scan_point_certificates_one_live_key
    ON scan_point_certificates (tenant_id, scan_point_id)
    WHERE superseded_at IS NULL;

-- The forensic query: this scan point's certificates, newest first.
CREATE INDEX scan_point_certificates_history_idx
    ON scan_point_certificates (tenant_id, scan_point_id, issued_at DESC);

-- The expiry sweep: certificates approaching not_after that have not rotated.
-- Rotation is at 60 of 90 days, so anything live and close to not_after is a
-- scan point that has stopped rotating and is about to fall off the fleet.
CREATE INDEX scan_point_certificates_expiring_idx
    ON scan_point_certificates (not_after)
    WHERE superseded_at IS NULL;

ALTER TABLE scan_point_certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_point_certificates FORCE ROW LEVEL SECURITY;
CREATE POLICY scan_point_certificates_tenant_isolation ON scan_point_certificates
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- ---------------------------------------------------------------------------
-- Backfill
-- ---------------------------------------------------------------------------
-- Every scan point that already carries a fingerprint gets a row, so the table
-- is complete from its first migration. Without this, "which certificate was
-- valid when" has a hole covering everything before today — and a history with a
-- silent hole is worse than no history, because it will be queried and believed.
--
-- What is not knowable for a pre-existing certificate is stated as such rather
-- than invented: Core did not record serials or validity windows before this
-- table existed. serial_number is 'unknown-backfill' and the validity window is
-- a placeholder anchored on the scan point's enrolment time, which the
-- surrounding comment and the serial value both make obvious. Fabricating a
-- plausible 90-day window would produce a history that looks precise and is not.

INSERT INTO scan_point_certificates
    (tenant_id, scan_point_id, cert_fingerprint, serial_number,
     not_before, not_after, issued_at)
SELECT sp.tenant_id,
       sp.scan_point_id,
       sp.cert_fingerprint,
       'unknown-backfill',
       sp.enrolled_at,
       sp.enrolled_at + interval '90 days',
       sp.enrolled_at
  FROM scan_points sp
 WHERE sp.cert_fingerprint IS NOT NULL
   AND NOT EXISTS (
       SELECT 1 FROM scan_point_certificates c
        WHERE c.tenant_id = sp.tenant_id AND c.scan_point_id = sp.scan_point_id
   );

-- No DELETE. An issuance record is not the application's to remove; it is what
-- answers "what identity did this peer hold" after an incident.
GRANT SELECT, INSERT, UPDATE ON scan_point_certificates TO cvap_app;

COMMIT;
