-- PostgreSQL cannot remove an enum value once added, so this down is a documented
-- no-op — the one-way shape ADD VALUE migrations carry. Rolling back the feature
-- means leaving 'refuted_by_credentialed' and 'superseded_by_credentialed' as unused
-- labels on finding_status; nothing writes them once the code that does is reverted.
SELECT 1;
