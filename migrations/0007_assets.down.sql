-- Down migration for 0007_assets

BEGIN;

REVOKE ALL ON assets, asset_addresses, asset_identity_keys, services,
              software_components, asset_relationships FROM cvap_app;

DROP TABLE IF EXISTS asset_relationships;
DROP TABLE IF EXISTS software_components;
DROP TABLE IF EXISTS services;
DROP TABLE IF EXISTS asset_identity_keys;
DROP TABLE IF EXISTS asset_addresses;
DROP TABLE IF EXISTS assets;

DROP TYPE IF EXISTS asset_relationship_type;
DROP TYPE IF EXISTS component_source;
DROP TYPE IF EXISTS identity_key_type;
DROP TYPE IF EXISTS asset_criticality;

COMMIT;
