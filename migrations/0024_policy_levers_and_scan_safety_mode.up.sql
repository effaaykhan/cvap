-- 0024_policy_levers_and_scan_safety_mode
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.

-- Two things a safety audit found reaching nothing, and one ADR-021 requires.
--
--   * scan_policies.max_concurrent_per_target did not exist. ADR-024's table
--     says the platform default is 20 and a policy may lower it; there was no
--     column to lower it with.
--   * time_windows and allowed_zones existed and were selected by nothing, so a
--     policy could carry a maintenance window or a zone restriction that no
--     dispatch decision ever read. They become load-bearing in this migration's
--     companion Go change, which is why their encoding and their empty case are
--     written down here rather than left to whoever reads the column next.
--   * scans.safety_mode did not exist, so ADR-021's "intrusive requires
--     explicit per-scan opt-in" had nothing to opt in with. One policy flipped
--     to intrusive standing-authorised every scan ever bound to it.
--
-- No new tables, so no new RLS policies: every column added here lands on a
-- table that already has tenant isolation (0003, 0005).

BEGIN;

-- ---------------------------------------------------------------------------
-- scan_policies.max_concurrent_per_target — ADR-024 control 2, lower-only
-- ---------------------------------------------------------------------------
-- Concurrency is a separate lever from rate rather than a derivative of it.
-- A host answering 20 simultaneous connects at 5 pps is under more pressure
-- than one answering a single connection at 50 pps, and connection count is
-- what tips a printer or an embedded device over. An operator who lowered
-- max_rate_pps to protect a fragile estate was still handed 20 concurrent
-- connections per host.
--
-- Shaped exactly like max_rate_pps above it: NULL means "platform default", the
-- CHECK bounds it at ADR-024's current default so a policy cannot be written
-- above it, and Core compares again against the configured ceiling before
-- anything reaches the wire. A ceiling enforced in only one place is decorative.

ALTER TABLE scan_policies
    ADD COLUMN max_concurrent_per_target int;

ALTER TABLE scan_policies
    ADD CONSTRAINT scan_policies_concurrency_lower_only
        CHECK (max_concurrent_per_target IS NULL
               OR (max_concurrent_per_target > 0 AND max_concurrent_per_target <= 20));

COMMENT ON COLUMN scan_policies.max_concurrent_per_target IS
    'NULL means "platform default" (20). Lower-only against the ADR-024 ceiling; see docs/adr/024-scan-blast-radius-controls.md for the authoritative table.';

-- ---------------------------------------------------------------------------
-- time_windows and allowed_zones — encoding, and what empty means
-- ---------------------------------------------------------------------------
-- Both default to '[]' on every row that already exists, and both therefore
-- take the UNRESTRICTED reading of empty. That is the opposite of
-- ScanConstraints.allowed_targets, where empty means DENY ALL, and the
-- difference is deliberate: ADR-037 records it so that the next reader does not
-- "fix" the inconsistency. These two columns answer "is this scan restricted",
-- and an unset restriction is no restriction. allowed_targets answers "where may
-- this scan reach", and the safe answer to an unset question is nowhere. One
-- enumerates constraint; the other enumerates permission.
--
-- The CHECKs pin the container type only. Everything inside is validated in
-- Core, fail-closed: a window Core cannot parse fails the job with an audit
-- event rather than being skipped, for the same reason an unparseable scope rule
-- does (ADR-024 control 1). A CHECK cannot express "22:00 is a time and
-- Europe/London is a zone this deployment can resolve", and half-validating in
-- two places is how the halves drift apart.

ALTER TABLE scan_policies
    ADD CONSTRAINT scan_policies_time_windows_is_array
        CHECK (jsonb_typeof(time_windows) = 'array');

ALTER TABLE scan_policies
    ADD CONSTRAINT scan_policies_allowed_zones_is_array
        CHECK (jsonb_typeof(allowed_zones) = 'array');

-- Dispatch parses every window of every windowed policy on every poll, for every
-- connected scan point, inside the transaction that claims work. Unbounded, one
-- policy measured at 122 ms per parse with ten thousand windows — minutes of CPU
-- per poll on a shared control plane, holding a pooled connection. Ten is
-- generous for a maintenance schedule; anything past it wants a cron expression
-- rather than a list. Mirrored as MaxWindowsPerPolicy in internal/dispatch, and
-- duplicated deliberately: the Go side must not trust the column, and a policy
-- over the cap should be impossible to WRITE rather than merely undispatchable.
ALTER TABLE scan_policies
    ADD CONSTRAINT scan_policies_time_windows_bounded
        CHECK (jsonb_array_length(time_windows) <= 10);

COMMENT ON COLUMN scan_policies.time_windows IS
    'Recurring maintenance windows. Array of {"start":"HH:MM","end":"HH:MM","days":["mon",...],"tz":"IANA"}; days and tz optional, defaulting to every day and UTC. end <= start crosses midnight. EMPTY MEANS UNRESTRICTED (ADR-037). Evaluated in Core; only the computed ScanConstraints.window_ends_unix travels.';

COMMENT ON COLUMN scan_policies.allowed_zones IS
    'Array of scan_zones.zone_id as text. A scan point outside the list cannot claim the job — enforced as a Jobs.Claim predicate, not as advice. EMPTY MEANS UNRESTRICTED (ADR-037). Zone ids rather than names because a name is editable and this is an authorisation input.';

-- Dispatch reads "which policies in this tenant have a window" on every poll,
-- and almost no policy will have one. A partial index keeps that a lookup
-- rather than a scan of every policy the tenant has ever written.
CREATE INDEX scan_policies_windowed_idx
    ON scan_policies (tenant_id)
    WHERE jsonb_array_length(time_windows) > 0;

-- ---------------------------------------------------------------------------
-- scans.safety_mode — ADR-021's per-scan opt-in
-- ---------------------------------------------------------------------------
-- The policy sets the CEILING; the scan must opt in beneath it. The effective
-- mode is the lower of the two, and that is what reaches the wire.
--
-- Defaulting to 'safe' means every scan that already exists, and every scan
-- written by anything that has not been taught about this column, is safe
-- regardless of its policy. That is the whole point: ADR-021 was written against
-- a policy left on intrusive after a test window, and a default of "inherit the
-- policy" would reproduce exactly that. It also means the ceiling can only ever
-- lower — an intrusive scan under a safe policy runs safe.
--
-- The ceiling cannot be a CHECK: it compares a column on this table against one
-- on scan_policies, and a CHECK sees a single row. It is enforced where the
-- opt-in is written (store.Scans.SetSafetyMode, which refuses to exceed the
-- policy and records the ADR-021 audit event in the same transaction) and again
-- in dispatch when constraints are built, because a ceiling enforced in one
-- place is decorative.

ALTER TABLE scans
    ADD COLUMN safety_mode safety_mode NOT NULL DEFAULT 'safe';

COMMENT ON COLUMN scans.safety_mode IS
    'ADR-021 per-scan opt-in. The effective mode is min(scan_policies.safety_mode, this) — a scan may only lower. Selecting intrusive emits an audit event; see store.Scans.SetSafetyMode.';

-- ---------------------------------------------------------------------------
-- The ceiling, made structural
-- ---------------------------------------------------------------------------
-- The paragraph above says the ceiling is enforced where the opt-in is written.
-- That was true of the only writer that exists and false of the table: cvap_app
-- holds column-wide INSERT and UPDATE on scans, so a future scan-creation API
-- could write safety_mode = 'intrusive' directly and never pass the check. The
-- blast radius was bounded — constraintsFor recomputes min(policy, scan) from
-- live rows before anything reaches the wire — but ADR-021 asks for the opt-in
-- to be explicit, and an invariant that holds only because today's callers
-- happen to be well-behaved is a convention, not a control.
--
-- A trigger can express what a CHECK cannot, because it may read another table.
-- Same argument as migration 0020's ingest_state ratchet: a GRANT cannot say
-- "this column may only be set one way" when every writer runs as the same role.
--
-- What this does NOT enforce is the audit event. No trigger can — an event is a
-- row in another table that a caller either writes or does not — so that half
-- stays a convention, and saying so here is better than a comment that reads as
-- enforcement.
CREATE OR REPLACE FUNCTION scans_safety_mode_within_policy()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_policy_mode safety_mode;
BEGIN
    IF NEW.safety_mode <> 'intrusive' THEN
        RETURN NEW;
    END IF;

    SELECT safety_mode INTO v_policy_mode
      FROM scan_policies
     WHERE tenant_id = NEW.tenant_id AND policy_id = NEW.policy_id;

    IF v_policy_mode IS DISTINCT FROM 'intrusive' THEN
        RAISE EXCEPTION
            'scan %: safety_mode intrusive exceeds its policy (ADR-021). The policy sets the ceiling and the scan opts in beneath it; use store.Scans.SetSafetyMode, which also writes the required audit event.',
            NEW.scan_id
            USING ERRCODE = 'check_violation';
    END IF;

    RETURN NEW;
END
$$;

COMMENT ON FUNCTION scans_safety_mode_within_policy() IS
    'ADR-021: a scan may not opt into a mode its policy does not permit. A CHECK cannot see scan_policies, and every writer runs as cvap_app, so the rule has to be a trigger to be a rule.';

CREATE TRIGGER scans_safety_mode_within_policy
    BEFORE INSERT OR UPDATE OF safety_mode, policy_id ON scans
    FOR EACH ROW EXECUTE FUNCTION scans_safety_mode_within_policy();

-- ---------------------------------------------------------------------------
-- allowed_zones element shape
-- ---------------------------------------------------------------------------
-- Validated at WRITE time, not in the claim predicate, and the difference
-- matters. Jobs.Claim reads allowed_zones on every poll; a ::uuid cast there
-- would make one malformed element raise and fail every claim in the TENANT
-- rather than just that policy's. Here a bad element is refused by the
-- statement that introduced it, named, with nothing else affected.
--
-- Well-formedness only. A syntactically valid zone id naming no zone is not
-- necessarily an error — a policy may name a zone that has no scan point yet —
-- so that case stays a matter for the operator rather than the database.
CREATE OR REPLACE FUNCTION scan_policies_allowed_zones_are_uuids()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_element text;
BEGIN
    FOR v_element IN SELECT jsonb_array_elements_text(NEW.allowed_zones)
    LOOP
        IF v_element IS NULL OR v_element !~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN
            RAISE EXCEPTION
                'scan policy %: allowed_zones entry % is not a scan_zones.zone_id. The list is an authorisation input read by Jobs.Claim; an entry it cannot match silently restricts the policy to no zone at all.',
                NEW.policy_id, coalesce(quote_literal(v_element), 'null')
                USING ERRCODE = 'check_violation';
        END IF;
    END LOOP;
    RETURN NEW;
END
$$;

CREATE TRIGGER scan_policies_allowed_zones_are_uuids
    BEFORE INSERT OR UPDATE OF allowed_zones ON scan_policies
    FOR EACH ROW EXECUTE FUNCTION scan_policies_allowed_zones_are_uuids();

-- ---------------------------------------------------------------------------
-- What a task target may look like
-- ---------------------------------------------------------------------------
COMMENT ON COLUMN scan_tasks.task_target IS
    'One target, compared against the policy allowlist by Core (internal/dispatch/scope.go permits) and again at the scan point. An ADDRESS or a hostname today: a CIDR-shaped value matches no CIDR allow rule and the job is refused with scope_violation_halt. A planner that decomposes a range into a range-sweep task must extend scopeMatches first (ADR-024 control 1).';

COMMIT;
