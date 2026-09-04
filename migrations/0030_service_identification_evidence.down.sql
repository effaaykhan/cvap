-- 0030_service_identification_evidence (down)
--
-- Written in the same sitting as the up, per .claude/skills/write-migration:
-- a down written later is a down that is wrong.
--
-- Dropping these columns DISCARDS evidence — certificates, host keys, and the
-- provenance of every identification. That is what a down migration is for and
-- it is worth stating plainly: this is not a reversible operation in the sense
-- that re-applying the up restores the data. It restores the shape.

BEGIN;

DROP INDEX IF EXISTS services_ssh_fingerprint_idx;
DROP INDEX IF EXISTS services_cert_fingerprint_idx;
DROP INDEX IF EXISTS services_with_tls_idx;

ALTER TABLE services
    DROP CONSTRAINT IF EXISTS services_safety_mode_known,
    DROP CONSTRAINT IF EXISTS services_identification_method_known,
    DROP CONSTRAINT IF EXISTS services_softmatch_has_no_product,
    DROP CONSTRAINT IF EXISTS services_identification_confidence_range,
    DROP COLUMN IF EXISTS ssh,
    DROP COLUMN IF EXISTS tls,
    DROP COLUMN IF EXISTS identification_probe,
    DROP COLUMN IF EXISTS safety_mode,
    DROP COLUMN IF EXISTS solicited,
    DROP COLUMN IF EXISTS softmatch,
    DROP COLUMN IF EXISTS identification_confidence,
    DROP COLUMN IF EXISTS identification_method;

COMMIT;
