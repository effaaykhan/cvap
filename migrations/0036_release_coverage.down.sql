-- 0036_release_coverage (down)

BEGIN;

REVOKE ALL ON release_coverage FROM cvap_app;
REVOKE ALL ON release_coverage FROM cvap_knowledge_import;

DROP TABLE IF EXISTS release_coverage;

COMMIT;
