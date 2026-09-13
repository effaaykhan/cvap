-- 0046_identity_confirmed
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.
--
-- ADR-097 (B39): an operator's word is the only verification an observed SSH
-- host key gets. A key recorded by a rotation or a lapse (ADR-096) is excluded
-- from the credentialed trust root and from establishment until an operator
-- confirms it; confirmation re-stamps the provenance to 'confirmed', which is
-- excluded from nothing and names who decided in the audit log. The queue's
-- operator verbs ("same host", "different host") record the keys they accept
-- with the same provenance. No new table, no new column: ADD VALUE only,
-- transactional on PostgreSQL 16 as long as the label is not used in the
-- same transaction, and nothing here uses it.

BEGIN;

ALTER TYPE identity_key_provenance ADD VALUE IF NOT EXISTS 'confirmed';

-- The SERVICE a parked key came from ("22/tcp"), canonicalised ONCE at
-- enqueue from the key's Source (the identity path's grammar) and read by the
-- listing, the ambiguity check and the operator's verbs alike. The review
-- measured the same fact spelled four ways — a Go trim, a SQL btrim, a display
-- expression and an index — and a tab in a payload's protocol splitting one
-- service into two: the listing offered no choice and every verb refused.
-- NULL for an address-only (ip_window) item. Backfilled from the copied
-- payload with the same lower/trim the identity path applies.
ALTER TABLE asset_resolution_queue ADD COLUMN source text;
UPDATE asset_resolution_queue
   SET source = (observed_payload ->> 'port') || '/' ||
                lower(regexp_replace(coalesce(nullif(observed_payload ->> 'protocol', ''), 'tcp'), '^\s+|\s+$', '', 'g'))
 WHERE source IS NULL AND key_type <> 'ip_window'
   AND jsonb_typeof(observed_payload -> 'port') = 'number';
-- A keyed row whose copied payload names no usable port (rows from before the
-- port was required on the identity path) gets the one word the guard treats
-- as a service of its own: it can be chosen or discarded like any other, and
-- it can never silently pass for another service's key.
UPDATE asset_resolution_queue SET source = 'unknown'
 WHERE source IS NULL AND key_type <> 'ip_window';
-- The guard that keeps an operator from confirming an unseen key skips
-- nothing: a keyed item ALWAYS has a service (Enqueue refuses one without).
ALTER TABLE asset_resolution_queue
    ADD CONSTRAINT asset_resolution_queue_keyed_has_source
        CHECK (key_type = 'ip_window' OR source IS NOT NULL);

COMMIT;
