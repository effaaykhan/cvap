-- 0035_release_resolution (P3.3, ADR-064)
--
-- Two things release resolution needs: the product->package association (content,
-- ADR-048/ADR-064 — the observed service product "OpenSSH" maps to the Ubuntu
-- source package "openssh" the advisory keyspace is keyed on), and somewhere to
-- store the release provenance so a resolved release carries its evidence the way
-- the family attribution does (ADR-061).

BEGIN;

-- ---------------------------------------------------------------------------
-- product_packages: the light product->package map. Global knowledge (no
-- tenant_id, ADR-030), the same class as the advisory tables: identification
-- content that grows with every service and every package rename, so it is a
-- reviewable, importable row set rather than a Go literal (ADR-048's corpus
-- argument). One product maps to one or more packages: MySQL spans mysql-dfsg-5.0
-- (hardy-era) through mysql-8.0, and band matching tolerates the rename because it
-- keys on the upstream band, not the exact name.
-- ---------------------------------------------------------------------------
CREATE TABLE product_packages (
    product      text NOT NULL,   -- matches the fingerprint's Product string ("OpenSSH", "MySQL")
    package_name text NOT NULL,   -- an Ubuntu source package the advisory keyspace uses
    PRIMARY KEY (product, package_name)
);

COMMENT ON TABLE product_packages IS
    'Product->Ubuntu-package association for release resolution (ADR-064). Global knowledge content (ADR-030/ADR-048); cvap_app reads, cvap_knowledge_import writes.';

-- The injection guarantee (ADR-063): the write role must never reach past its
-- grants via RLS bypass. Re-asserted here because this migration adds to its grants.
DO $$
DECLARE r record;
BEGIN
    SELECT rolbypassrls, rolsuper INTO r FROM pg_roles WHERE rolname = 'cvap_knowledge_import';
    IF r.rolbypassrls THEN
        RAISE EXCEPTION 'cvap_knowledge_import holds BYPASSRLS (ADR-063). Fix: ALTER ROLE cvap_knowledge_import NOBYPASSRLS;';
    END IF;
    IF r.rolsuper THEN
        RAISE EXCEPTION 'cvap_knowledge_import is SUPERUSER (ADR-063). Fix: ALTER ROLE cvap_knowledge_import NOSUPERUSER;';
    END IF;
END $$;

-- cvap_app reads the map during correlation; only the import role writes it.
GRANT SELECT ON product_packages TO cvap_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON product_packages TO cvap_knowledge_import;

-- Release resolution joins advisory_fixed_packages on package_name ALONE (no
-- release predicate — the whole point is to find which releases a package's bands
-- span). 0010's only package index leads with distro_release, so it cannot serve
-- this equality; without this index ReleasesForProduct is a seq scan per resolved
-- product, on a table that only grows with every ingested advisory (schema-auditor,
-- S31). FixesFor (release-first) keeps using 0010's index; this is the other read.
CREATE INDEX advisory_fixed_packages_by_package_idx
    ON advisory_fixed_packages (package_name);

-- ---------------------------------------------------------------------------
-- Release provenance on the asset. distro_release already exists (0033, the
-- three-state model); these add the release verdict's OWN confidence and
-- evidence chain, kept separate from os_provenance (which is the FAMILY chain) so
-- the asset page can show "how the release was concluded" distinctly from "how
-- the family was concluded" — a resolved release with no visible evidence is a
-- claim an operator cannot check (ADR-061).
-- ---------------------------------------------------------------------------
ALTER TABLE assets
    ADD COLUMN release_confidence real,
    ADD COLUMN release_provenance jsonb;

COMMIT;
