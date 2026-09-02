-- 0021_task_asset_link
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.

-- scan_tasks gains a link to the asset it targets, so `fragile` can travel.
--
-- ============================================================================
-- Why this is a schema gap and not a one-line omission.
-- ============================================================================
--
-- ADR-024 control 3 makes `fragile` a first-class asset attribute that caps rate
-- REGARDLESS of policy, and Task.fragile on the wire exists to carry it per
-- task, because fragility belongs to the device rather than to the scan — it
-- must apply to every scan that ever touches that device, including one written
-- by someone who has never heard of it.
--
-- assets.fragile has existed since migration 0007. ScanConstraints.fragile_rate_pps
-- travels on every assignment. And nothing connected the two: scan_tasks reaches
-- scan_targets, which reaches scans, and that chain never touches assets. So the
-- runtime was being told the fragile rate and never told which task it applied
-- to — a ceiling with no subject, which is the decorative kind ADR-024 warns
-- about.
--
-- Nullable, because a task's asset is not always known. Discovery finds hosts
-- that have no asset yet; that is the normal case for the engine this session
-- builds. A task with no asset is treated as NOT fragile, which is the
-- permissive direction — stated here rather than left implicit, because the safe
-- direction would be to treat unknown as fragile and that would throttle every
-- discovery scan to 10 pps. Correlation attaches the asset once it exists, and a
-- device known to be fragile is one Core has already seen.

BEGIN;

DO $$
DECLARE r record;
BEGIN
    SELECT rolbypassrls, rolsuper INTO r FROM pg_roles WHERE rolname = 'cvap_app';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Role cvap_app does not exist (ADR-002)';
    END IF;
    IF r.rolbypassrls OR r.rolsuper THEN
        RAISE EXCEPTION 'Role cvap_app can bypass RLS (ADR-002). Fix: ALTER ROLE cvap_app NOBYPASSRLS NOSUPERUSER;';
    END IF;
END
$$;

ALTER TABLE scan_tasks ADD COLUMN asset_id uuid;

-- Composite FK (ADR-017): a task in tenant A cannot target an asset in tenant B.
-- Column-list SET NULL (Postgres 15+) so a deleted asset does not take the
-- record of the work with it — and does not try to null tenant_id, which is
-- NOT NULL.
ALTER TABLE scan_tasks
    ADD CONSTRAINT scan_tasks_asset_fk FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, asset_id) ON DELETE SET NULL (asset_id);

COMMENT ON COLUMN scan_tasks.asset_id IS
    'The asset this task targets, once known. Nullable: discovery finds hosts before assets exist. Its only current consumer is ADR-024''s fragile cap — Jobs.Tasks joins assets.fragile through here so Task.fragile can travel on the wire. A task with no asset is treated as not fragile.';

-- Dispatch joins this on every assignment.
CREATE INDEX scan_tasks_asset_idx ON scan_tasks (tenant_id, asset_id)
    WHERE asset_id IS NOT NULL;

COMMIT;
