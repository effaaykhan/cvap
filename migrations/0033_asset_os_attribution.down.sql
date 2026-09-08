-- 0033_asset_os_attribution (down)

ALTER TABLE assets
    DROP COLUMN distro_family,
    DROP COLUMN distro_release,
    DROP COLUMN os_confidence,
    DROP COLUMN os_provenance;
