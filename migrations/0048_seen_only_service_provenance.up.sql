-- Admit 'discovery' as an identification_method (ADR-104, correcting ADR-103).
--
-- An open port found by the discovery engine is durable evidence: it is the
-- asset's attack surface, and the observation carrying it is ephemeral
-- (ADR-016), so correlation promotes it to a `services` row. That row identifies
-- nothing — it records only that the port answered.
--
-- 'discovery' stays DISTINCT from 'none', and the distinction is the reason this
-- migration exists rather than a reuse:
--
--     'none'      a probe ran and identified nothing
--     'discovery' nothing probed it; the port merely answered
--
-- Different strengths of evidence about the same endpoint. A reader deciding
-- whether to trust the row, or a later change deciding whether the endpoint is
-- worth fingerprinting, needs to tell them apart.
--
-- No RLS or grant change: `services` already carries tenant_id, row level
-- security, FORCE, and a policy with both USING and WITH CHECK, and this alters
-- a CHECK only. The assertion below is the house rule repeated rather than
-- assumed — a migration that touches a tenant-scoped table states what it
-- believes about that table's protection, so a regression is caught by the
-- migration that introduces it rather than by a review that might not run.

ALTER TABLE services DROP CONSTRAINT services_identification_method_known;

ALTER TABLE services ADD CONSTRAINT services_identification_method_known
    CHECK (identification_method IS NULL
           OR identification_method = ANY (ARRAY[
               'banner', 'probe', 'tls-probe', 'ssh-kex', 'tls', 'none',
               -- ADR-104: the port answered and nothing identified it.
               'discovery']));

DO $$
DECLARE
    rls   boolean;
    force boolean;
    pols  integer;
BEGIN
    SELECT relrowsecurity, relforcerowsecurity INTO rls, force
      FROM pg_class WHERE oid = 'services'::regclass;
    SELECT count(*) INTO pols
      FROM pg_policies
     WHERE tablename = 'services' AND qual IS NOT NULL AND with_check IS NOT NULL;

    IF NOT rls OR NOT force THEN
        RAISE EXCEPTION
            'services lost row level security (rls=%, force=%) — every tenant policy on it is inert (ADR-002).',
            rls, force;
    END IF;
    IF pols = 0 THEN
        RAISE EXCEPTION
            'services has no policy carrying BOTH USING and WITH CHECK; a USING-only policy lets a tenant write into another tenant''s scope (ADR-002).';
    END IF;
    RAISE NOTICE 'services: RLS forced, % policy(ies) with USING + WITH CHECK', pols;
END
$$;
