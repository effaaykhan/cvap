-- 0035_release_resolution (down)

BEGIN;

ALTER TABLE assets
    DROP COLUMN IF EXISTS release_provenance,
    DROP COLUMN IF EXISTS release_confidence;

DROP INDEX IF EXISTS advisory_fixed_packages_by_package_idx;

REVOKE ALL ON product_packages FROM cvap_app;
REVOKE ALL ON product_packages FROM cvap_knowledge_import;

DROP TABLE IF EXISTS product_packages;

COMMIT;
