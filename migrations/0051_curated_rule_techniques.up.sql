-- 0051_curated_rule_techniques (ADR-105 decision 2, anchor 2)
--
-- The curated rule -> ATT&CK mappings. Separate from 0050 because that migration
-- is schema and this is CONTENT: rules 15 and 16 will want their own rows, and a
-- later revision of a judgement made here should be readable as a diff against
-- this file rather than buried in a table definition.
--
-- ELEVEN OF FOURTEEN RULES ARE MAPPED, AND THE OTHER THREE ARE LEFT ALONE ON
-- PURPOSE. ADR-105 decision 4 says absence must read as "we have no mapping" and
-- never as "no technique applies", so the three are simply absent rather than
-- recorded as deliberate non-mappings — a row saying "nothing applies here"
-- would be the stronger claim the decision forbids. The reasoning is here
-- instead, where it is reviewable without being assertable:
--
--   advisory-version-match        This is the CVE-bearing rule. Its findings
--                                 carry a vuln_def_id, so anchor 1 reaches them
--                                 when the published dataset has a mapping.
--                                 Curating a blanket technique for "some package
--                                 is out of date" would attach the same
--                                 inference to every advisory finding CVAP ever
--                                 raises, which is precisely the plausible-at-
--                                 volume output ADR-105 rejected.
--   tls-certificate-expiring-soon A forecast, not a present weakness. The
--                                 certificate is still valid; nothing is
--                                 exploitable yet. A technique here would
--                                 describe a state the host is not in.
--   http-missing-security-headers CWE-693 covers browser-side defence in depth.
--                                 The honest technique would be about what an
--                                 adversary does to a VISITOR after a separate
--                                 initial compromise, which is a claim about a
--                                 different asset than the one carrying the
--                                 finding.
--
-- WHY THESE TECHNIQUES. Every row below is an inference about what the weakness
-- ENABLES, phrased against the weakness rather than the host. Two techniques do
-- almost all the work, which is a property of what these rules detect rather
-- than a shortcut:
--
--   T1040  Network Sniffing            — the traffic is readable on the wire
--   T1557  Adversary-in-the-Middle     — the channel cannot be authenticated
--   T1133  External Remote Services    — a remote service is reachable it
--                                        should not be
--
-- The mapping keys on rule NAME within the builtin pack, not on rule_id: rule_id
-- is gen_random_uuid() and differs per database, so a literal here would bind
-- this content to one installation.

BEGIN;

INSERT INTO rule_techniques (rule_id, technique_id, source, rationale)
SELECT r.rule_id, v.technique_id, 'cvap-curated', v.rationale
  FROM (VALUES
    -- Cleartext protocols: the traffic is readable by anyone on the path, and it
    -- carries credentials. Both techniques apply and for different reasons, so
    -- both are recorded rather than picking the tidier one.
    ('plaintext-telnet', 'T1040',
     'Telnet carries the session, including authentication, as cleartext, so anyone on the network path can read credentials and commands directly off the wire.'),
    ('plaintext-telnet', 'T1557',
     'With no transport authentication an on-path adversary can modify the session as well as read it; Telnet offers nothing to detect the substitution.'),
    ('plaintext-ftp', 'T1040',
     'FTP authenticates in cleartext, so credentials and transferred file contents are readable by anyone on the network path.'),
    ('plaintext-ftp', 'T1557',
     'FTP has no transport integrity, so an on-path adversary can alter transferred content or redirect the data channel without the client detecting it.'),
    ('http-no-https-redirect', 'T1040',
     'A service reachable over plain HTTP exposes session cookies and form submissions to anyone on the network path.'),
    ('http-no-https-redirect', 'T1557',
     'Without an enforced redirect a client can be held on HTTP by an on-path adversary, who then controls the content it receives (the classic SSL-strip position).'),

    -- Exposure: the weakness is reachability, not the protocol.
    ('management-interface-untrusted-zone', 'T1133',
     'A management interface answering from an untrusted zone is an externally reachable remote service, usable for initial access and for re-entry afterwards without any further compromise.'),

    -- TLS trust: the channel exists but cannot be authenticated, which is the
    -- precondition for an on-path adversary rather than for passive reading.
    ('tls-self-signed-non-dev', 'T1557',
     'A self-signed certificate outside a development context gives the client no trust anchor to validate against, so a substituted certificate is indistinguishable from the real one.'),
    ('tls-missing-chain', 'T1557',
     'An incomplete chain makes validation fail for correct clients, and the usual operational response -- teaching clients to skip validation -- removes the defence that would detect an on-path adversary.'),
    ('tls-certificate-expired', 'T1557',
     'An expired certificate produces a warning users and clients are routinely told to click through, which is the same warning a substituted certificate would produce.'),

    -- TLS strength: the channel is authenticated but the cryptography does not
    -- hold, so both reading and interposition are in reach.
    ('tls-weak-key', 'T1557',
     'A key below current strength can be attacked directly; recovering it lets an adversary present the real certificate and hold the on-path position undetected.'),
    ('tls-weak-key', 'T1040',
     'Recorded traffic protected by an inadequate key can be decrypted after the fact, so capture now and read later is available to a passive adversary.'),
    ('tls-weak-cipher-negotiated', 'T1557',
     'A negotiated cipher with known weaknesses undermines the integrity of the session, which is what would otherwise prevent an on-path adversary from modifying it.'),
    ('tls-weak-cipher-negotiated', 'T1040',
     'Weak negotiated ciphers are the ones for which practical decryption of captured traffic exists.'),
    ('tls-legacy-version-negotiated', 'T1557',
     'Legacy TLS versions carry known downgrade and renegotiation flaws that put an adversary on the path of a session both endpoints believe is protected.'),
    ('ssh-weak-algorithms', 'T1557',
     'Weak SSH key exchange or MAC algorithms undermine the guarantee that the peer is the host it claims to be, which is the property that makes SSH resistant to interposition.')
  ) AS v(rule_name, technique_id, rationale)
  JOIN rules r ON r.name = v.rule_name
  JOIN rule_packs rp ON rp.rule_pack_id = r.rule_pack_id AND rp.name = 'cvap-builtin'
ON CONFLICT (rule_id, technique_id) DO UPDATE
   SET rationale = excluded.rationale, source = excluded.source;

-- The join above silently produces nothing for a rule name that does not exist,
-- which would leave this migration "successful" and the table short. Sixteen
-- rows over eleven distinct rules is what the content above says; assert it.
DO $$
DECLARE rows_written integer; rules_covered integer; total_rules integer;
BEGIN
    SELECT count(*), count(DISTINCT rule_id) INTO rows_written, rules_covered FROM rule_techniques;
    SELECT count(*) INTO total_rules FROM rules;
    IF rows_written <> 16 OR rules_covered <> 11 THEN
        RAISE EXCEPTION
            'curated rule techniques: wrote % row(s) over % rule(s), expected 16 over 11. A rule name in this migration no longer matches a row in `rules`, so the JOIN dropped it silently.',
            rows_written, rules_covered;
    END IF;
    RAISE NOTICE 'curated rule techniques: % rows, % of % rules mapped (ADR-105 decision 4: the other % read as unmapped, not as unaffected)',
        rows_written, rules_covered, total_rules, total_rules - rules_covered;
END $$;

COMMIT;
