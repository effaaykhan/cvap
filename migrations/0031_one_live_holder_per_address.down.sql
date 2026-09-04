-- 0031_one_live_holder_per_address (down)
--
-- Written in the same sitting as the up.
--
-- Restores 0007's non-unique index, because the reverse lookup it served —
-- "which asset currently holds this IP" — is on correlation's hot path and
-- dropping the unique index without it would turn every address lookup into a
-- sequential scan.

BEGIN;

DROP INDEX IF EXISTS asset_addresses_one_live_holder_idx;

CREATE INDEX asset_addresses_by_ip_idx
    ON asset_addresses (tenant_id, ip_address) WHERE valid_to IS NULL;

COMMIT;
