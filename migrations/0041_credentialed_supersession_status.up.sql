-- Credentialed supersession (Phase 4, ADR-077/087/088, session-40 spec).
--
-- When a credentialed read (exact installed version) resolves an inferred,
-- banner-derived finding for the same (asset, package, cve), the inferred finding
-- closes with a reason that says WHY: the credentialed read refuted it (the exact
-- version is not vulnerable — the ADR-078 false-positive case, most of them on a
-- maintained host) or superseded it (the exact version is vulnerable and the
-- credentialed finding carries the claim forward). Both are terminal states distinct
-- from 'remediated' (the vuln was fixed) and 'closed' (generic): they record that a
-- STRONGER source overruled a weaker one, which an operator triaging must be able to
-- see — sixteen inferred candidates refuted is an action, not a silent vanish.
--
-- finding_source already carries 'credentialed' (migration 0011); this adds the two
-- terminal statuses. Enum values cannot be removed in PostgreSQL, so the down is a
-- documented no-op — the same one-way shape every ADD VALUE migration has.

ALTER TYPE finding_status ADD VALUE IF NOT EXISTS 'refuted_by_credentialed';
ALTER TYPE finding_status ADD VALUE IF NOT EXISTS 'superseded_by_credentialed';
