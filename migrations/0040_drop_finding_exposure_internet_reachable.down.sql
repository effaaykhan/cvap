-- Down: restore the column and its partial index exactly as 0011 had them. It
-- comes back NOT NULL DEFAULT false — i.e. as dead as it was — which is the honest
-- reversal: the down does not resurrect a writer that never existed.
BEGIN;

ALTER TABLE finding_exposure ADD COLUMN internet_reachable boolean NOT NULL DEFAULT false;

CREATE INDEX finding_exposure_internet_idx
    ON finding_exposure (tenant_id, last_confirmed DESC)
    WHERE internet_reachable;

COMMIT;
