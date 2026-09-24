-- Reverse ADR-104's widening.
--
-- Rows written as 'discovery' must go first: the narrower constraint cannot be
-- added while they exist, and failing halfway would leave the table with no
-- identification_method constraint at all. They are set to NULL rather than
-- deleted — the endpoint was really seen, and the CHECK permits NULL — so the
-- down loses the provenance and keeps the fact.

UPDATE services SET identification_method = NULL
 WHERE identification_method = 'discovery';

ALTER TABLE services DROP CONSTRAINT services_identification_method_known;

ALTER TABLE services ADD CONSTRAINT services_identification_method_known
    CHECK (identification_method IS NULL
           OR identification_method = ANY (ARRAY[
               'banner', 'probe', 'tls-probe', 'ssh-kex', 'tls', 'none']));
