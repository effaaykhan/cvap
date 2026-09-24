-- Reverse ADR-104's widening.
--
-- Rows written as 'discovery' must go first: the narrower constraint cannot be
-- added while they exist (measured — the ADD raises 23514, "violated by some
-- row"). They are set to NULL rather than deleted: the endpoint really was
-- seen, and the CHECK permits NULL, so this loses the provenance and keeps the
-- fact.
--
-- What happens WITHOUT the UPDATE was measured rather than guessed, because the
-- first version of this comment claimed the wrong thing. golang-migrate runs
-- the file in one implicit transaction, so the DROP rolls back with the failed
-- ADD and the table keeps its wide constraint intact; the damage is a dirty
-- schema_migrations at 47 needing `migrate force`, not an unconstrained table.
--
-- One thing this does not undo: after down-then-up, ex-'discovery' rows stay
-- NULL. They are then indistinguishable from rows that never had a method set,
-- until the next discovery scan rewrites them — which is exactly the state
-- ADR-104 rejected as a design, arrived at by a round trip.

UPDATE services SET identification_method = NULL
 WHERE identification_method = 'discovery';

ALTER TABLE services DROP CONSTRAINT services_identification_method_known;

ALTER TABLE services ADD CONSTRAINT services_identification_method_known
    CHECK (identification_method IS NULL
           OR identification_method = ANY (ARRAY[
               'banner', 'probe', 'tls-probe', 'ssh-kex', 'tls', 'none']));
