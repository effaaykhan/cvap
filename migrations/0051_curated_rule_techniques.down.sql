-- Remove the curated rule -> technique mappings.
--
-- Scoped to `cvap-curated` rather than truncating the table: 0050's schema allows
-- other sources, and a down migration that removed rows it did not write would
-- destroy content belonging to whatever added them.

BEGIN;

DELETE FROM rule_techniques WHERE source = 'cvap-curated';

COMMIT;
