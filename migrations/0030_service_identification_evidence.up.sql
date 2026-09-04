-- 0030_service_identification_evidence
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.

-- What the fingerprint engine learned, carried onto the derived service row.
--
-- `services` was written before there was an engine to fill it, and it holds a
-- product, a version and a version confidence. Session 13's engine produces
-- considerably more, and all of it is load-bearing for what comes next:
--
--   - HOW the service was identified, and whether we PROVOKED it. An operator
--     asks "did we touch this host"; the finding pipeline asks "how much do I
--     believe this"; an auditor asks "was this within its authorisation". Three
--     different questions, three columns, and none of them derivable from the
--     others.
--   - SOFTMATCH: "this is HTTP, product unknown" is a correct answer, not a
--     failed one (ADR-048). Without a column it is indistinguishable from "we
--     did not look", which is the distinction the whole idea rests on.
--   - The TLS certificate and the SSH host key.
--
-- The last two are jsonb ON THIS ROW rather than tables of their own, and that
-- is ADR-048 §5's argument carried into the derived model: a certificate is a
-- property of a service on a port. Week 6's non-CVE rules ask "does this HTTPS
-- service present an expired certificate" and "is this key below 2048 bits", and
-- normalising the certificate makes every one of those a join.
--
-- The provenance stays SCALAR for the opposite reason: those are values the
-- finding pipeline filters and sorts on, and a column the planner can index is
-- not the same thing as a key inside a document.

BEGIN;

ALTER TABLE services
    -- How this service was identified. A CLOSED vocabulary, constrained below.
    --
    -- Free text was the first draft, reasoned from ADR-006's open
    -- observation_type. That reasoning does not transfer: observation_type is
    -- open on the WIRE because engines are extensible and a closed wire enum
    -- makes every new type a protocol change — and ADR-006 still has Core
    -- validate it against a closed set at ingest. This column is the derived
    -- side, written only by Core, so the closed set belongs here where the
    -- database can hold it.
    --
    -- A CHECK rather than an enum type, which is a deviation from house style —
    -- 0007 and 0013 use native enums for every other closed vocabulary — so it
    -- needs the actual reason rather than the one first written here.
    --
    -- `ALTER TYPE ... ADD VALUE` cannot be used in the same transaction that
    -- adds it. Every migration in this repository is one transaction, so
    -- widening an enum and then writing a row that uses the new value takes two
    -- migrations. A CHECK constraint can be dropped, recreated and used
    -- immediately.
    --
    -- The first draft argued "a new method should be a reviewed change", which
    -- an audit correctly pointed out does not distinguish the two: widening an
    -- enum is a reviewed migration as well.
    ADD COLUMN identification_method text,

    -- Distinct from version_confidence, which is about the VERSION string. This
    -- is about the identification as a whole: a service named by a banner it
    -- volunteered and one inferred from the shape of an error page are different
    -- evidence, and ADR-014 makes confidence decide how a finding is presented.
    ADD COLUMN identification_confidence numeric(4,3),

    -- Protocol known, product not. A correct answer.
    ADD COLUMN softmatch boolean NOT NULL DEFAULT false,

    -- Whether bytes left the scan point first. NOT derivable from
    -- identification_method: a banner read on a connection opened by a probe is
    -- still solicited, and this is the column an operator reads when asked what
    -- was touched.
    ADD COLUMN solicited boolean NOT NULL DEFAULT false,

    -- The effective mode the scan ran under (ADR-021). Recorded so a service
    -- identified under an intrusive job can be told from one identified under a
    -- safe one, which is the difference between "we asked" and "it told us".
    ADD COLUMN safety_mode text,

    -- Which probe produced this, so a claim can be traced to what was sent.
    ADD COLUMN identification_probe text,

    -- The certificate: negotiated version, cipher, ALPN, and a bounded chain.
    -- Bounded by the engine before it ever reaches here (chain depth, SAN count,
    -- name length), because a certificate from a scanned host is
    -- attacker-controlled by definition.
    ADD COLUMN tls jsonb,

    -- The SSH host key and the algorithms the server offered. `ssh-rsa` still on
    -- the list is a week 6 finding, and the fingerprint is ADR-007's
    -- `ssh_hostkey` identity key.
    ADD COLUMN ssh jsonb,

    ADD CONSTRAINT services_identification_confidence_range
        CHECK (identification_confidence IS NULL
               OR identification_confidence BETWEEN 0 AND 1),

    -- A softmatch is "protocol known, product NOT". A row claiming both is two
    -- different answers, and the engine derives softness from the product it
    -- ends up with — so this would be a database row the producer disagrees
    -- with. The same check the runtime makes against a signed pack (ADR-048).
    --
    -- The empty string counts as absent, and leaving it out was a real bug a
    -- schema audit demonstrated by inserting a row. `enginewire.Match.Product`
    -- is a `string` whose documented empty value IS the softmatch, Go's zero
    -- value for it is "" and not NULL, and nothing between the engine and here
    -- translates one into the other. Without this clause every legitimate
    -- softmatch write would be rejected — the exact opposite of a constraint
    -- whose purpose is to let "protocol known, product unknown" be stored as the
    -- correct answer it is.
    --
    -- Written into the constraint rather than fixed by normalising at the write
    -- boundary, because the write boundary does not exist yet: a rule that
    -- depends on discipline in code nobody has written is a rule that will be
    -- discovered the hard way.
    ADD CONSTRAINT services_softmatch_has_no_product
        CHECK (NOT softmatch OR product IS NULL OR product = ''),

    ADD CONSTRAINT services_identification_method_known
        CHECK (identification_method IS NULL OR identification_method IN (
            'banner',     -- it announced itself; nothing was sent
            'probe',      -- a payload was sent and the reply matched
            'tls-probe',  -- as above, through a TLS handshake
            'ssh-kex',    -- a key exchange completed
            'tls',        -- a certificate was obtained and no rule fired
            'none'        -- the port was open and nothing was learned
        )),

    -- ADR-021's two modes. A third value here would mean a scan ran under a
    -- mode this schema does not know, which is exactly the case that must not
    -- pass silently.
    ADD CONSTRAINT services_safety_mode_known
        CHECK (safety_mode IS NULL OR safety_mode IN ('safe', 'intrusive'));

COMMENT ON COLUMN services.tls IS
    'Certificate evidence for this service, ADR-048 §5: a property of a service on a port, not its own entity. Do not normalise without reworking the week 6 rules that read it.';

COMMENT ON COLUMN services.ssh IS
    'SSH host key and offered algorithms. The fingerprint is ADR-007 ssh_hostkey, the only identity key above weak that most Linux hosts can offer.';

COMMENT ON COLUMN services.solicited IS
    'Whether this scan point sent bytes first. Not derivable from identification_method; it is what an operator reads when asked what was touched.';

-- Week 6 walks services by what they are running, and the certificate rules walk
-- the ones that have a certificate at all. A partial index because most services
-- have none.
CREATE INDEX services_with_tls_idx
    ON services (tenant_id, asset_id) WHERE tls IS NOT NULL;

-- Correlation's reverse lookup for ADR-007's service_cert_fp and ssh_hostkey:
-- given a fingerprint, which service currently holds it. Expression indexes over
-- the jsonb, so the identity path does not sequential-scan the services table
-- once an estate is real.
CREATE INDEX services_cert_fingerprint_idx
    ON services (tenant_id, (tls -> 'chain' -> 0 ->> 'fingerprint'))
    WHERE tls IS NOT NULL;

CREATE INDEX services_ssh_fingerprint_idx
    ON services (tenant_id, (ssh ->> 'fingerprint'))
    WHERE ssh IS NOT NULL;

COMMIT;
