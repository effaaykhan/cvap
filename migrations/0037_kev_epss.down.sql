-- 0037_kev_epss (down)

BEGIN;

REVOKE ALL ON kev, epss FROM cvap_app;
REVOKE ALL ON kev, epss FROM cvap_knowledge_import;

DROP TABLE IF EXISTS epss;
DROP TABLE IF EXISTS kev;

COMMIT;
