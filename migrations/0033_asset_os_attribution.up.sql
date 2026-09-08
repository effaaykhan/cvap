-- 0033_asset_os_attribution
--
-- OS attribution derived from unauthenticated service banners (B21, ADR-061).
-- Added to `assets`, which already carries tenant_id and its RLS policy from
-- migration 0007 (asset_tenant_isolation), so these nullable columns are covered
-- by that policy and need no new one — no tenant-scoped table is being created.
--
-- Three-state model (ADR-061), representable in the nullability rather than an
-- overloaded null that means two things:
--
--   distro_family NULL                       -> NO ATTRIBUTION ("know nothing")
--   distro_family SET, distro_release NULL   -> FAMILY-ONLY ("Ubuntu, no feed";
--                                               a credentialed-follow-up candidate,
--                                               unmatched for advisory purposes
--                                               per ADR-014)
--   distro_family SET, distro_release SET    -> RESOLVED (matchable)
--
-- distro_release stays NULL from banners: reaching ubuntu804 needs a
-- package-version->release map, which is knowledge-pipeline content, not banner
-- extraction. os_provenance carries which services contributed, agreed and were
-- ignored, so a wrong attribution's basis is reachable (ADR-061), the same reason
-- a finding carries its evidence.

ALTER TABLE assets
    ADD COLUMN distro_family  text,
    ADD COLUMN distro_release text,
    ADD COLUMN os_confidence  real,
    ADD COLUMN os_provenance  jsonb;
