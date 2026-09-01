-- Down migration for 0010_knowledge

BEGIN;

REVOKE ALL ON rule_packs, rules, vulnerability_defs, rule_vuln_map,
              vendor_advisories, advisory_vuln_map, advisory_fixed_packages
    FROM cvap_app;

DROP TABLE IF EXISTS advisory_fixed_packages;
DROP TABLE IF EXISTS advisory_vuln_map;
DROP TABLE IF EXISTS vendor_advisories;
DROP TABLE IF EXISTS rule_vuln_map;
DROP TABLE IF EXISTS vulnerability_defs;
DROP TABLE IF EXISTS rules;
DROP TABLE IF EXISTS rule_packs;

DROP TYPE IF EXISTS version_comparator;
DROP TYPE IF EXISTS execution_site;
DROP TYPE IF EXISTS severity;

COMMIT;
