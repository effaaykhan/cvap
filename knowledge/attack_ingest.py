#!/usr/bin/env python3
"""MITRE ATT&CK ingestion — ADR-105 (ADR-063, ADR-019).

Two feeds, same shape as knowledge/risk_ingest.py: fetch (online) -> a normalized
pack (JSON, with provenance) -> import (offline, idempotent) via CSV + \\copy into
TEMP staging, as cvap_knowledge_import (ADR-063).

  corpus    the ATT&CK enterprise technique catalogue, at a PINNED version
  mappings  a published CVE -> technique dataset (CTID Mappings Explorer)

WHAT THESE ROWS ARE. Every mapping is an INFERENCE about a weakness — someone
reasoning about what an adversary COULD do — never a record of anything observed.
CVAP does not exploit anything (non-negotiable #9), so it is in no position to
report how something WAS exploited. ADR-105 decision 3 makes that labelling part
of the contract, which is why `source` is carried on every row and why no
confidence number is ever invented here: this source publishes none, so the
column stays NULL and the source's own `mapping_type` is carried verbatim.

RETIREMENT, NOT DELETION (ADR-105 consequences). Neither importer deletes. A
technique that leaves a later corpus keeps its row and gains `deprecated` or
`revoked_by`, because a finding that cited it must still be able to explain
itself.
"""

import argparse
import csv
import datetime
import json
import os
import shutil
import subprocess
import sys
import tempfile

# PINNED, and pinned TOGETHER. The mapping dataset declares which ATT&CK version
# it was authored against; the catalogue must be that same version or the
# mappings name techniques the catalogue does not have. Bumping one of these
# without the other is the drift ADR-105 warns about, and `import-mappings`
# refuses rather than letting it land quietly.
ATTACK_VERSION = "16.1"
CORPUS_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    f"enterprise-attack/enterprise-attack-{ATTACK_VERSION}.json"
)

MAPPING_SOURCE = "ctid-mappings-explorer"
MAPPING_VERSION = "kev-07.28.2025"
MAPPINGS_URL = (
    "https://raw.githubusercontent.com/center-for-threat-informed-defense/"
    f"mappings-explorer/main/mappings/kev/attack-{ATTACK_VERSION}/{MAPPING_VERSION}/"
    f"enterprise/{MAPPING_VERSION}_attack-{ATTACK_VERSION}-enterprise.json"
)

# Hostile-input bounds; refusals, never truncations (ADR-069's rule, applied
# here). The corpus is ~46MB of STIX and grows with each release.
MAX_FEED_BYTES = 192 * 1024 * 1024
MAX_TECHNIQUES = 20000                    # enterprise 16.1 is ~800
MAX_MAPPINGS = 200000                     # the KEV dataset is ~1,200
MAX_FIELD = 4096
MAX_DESCRIPTION = 64 * 1024

ATTACK_STALENESS = "180 days"             # ATT&CK ships roughly twice a year


def _bounded(v, n=MAX_FIELD):
    if v is None:
        return None
    s = str(v)
    if len(s) > n:
        raise SystemExit(f"REFUSED: a feed field exceeds {n} bytes ({s[:60]!r}...).")
    return s


def _read_capped(resp, cap):
    buf = bytearray()
    while True:
        chunk = resp.read(65536)
        if not chunk:
            break
        buf += chunk
        if len(buf) > cap:
            raise SystemExit(f"REFUSED: feed body exceeds {cap} bytes — refused, not truncated (ADR-069).")
    return bytes(buf)


def _sql_lit(v):
    if v is None:
        return "NULL"
    return "'" + str(v).replace("'", "''") + "'"


def _urlopen(url):
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "CVAP-knowledge/attack (ADR-019)"})
    return urllib.request.urlopen(req, timeout=120)  # noqa: S310 (fixed https hosts)


def _refuse_oversized(pack_path):
    size = os.path.getsize(pack_path)
    if size > MAX_FEED_BYTES:
        raise SystemExit(f"REFUSED: pack {pack_path} is {size} bytes, over the {MAX_FEED_BYTES} bound.")


def _run_psql(db_url, sql):
    proc = subprocess.run(["psql", db_url, "-v", "ON_ERROR_STOP=1", "-q"],
                          input=sql, text=True, capture_output=True)
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    if proc.returncode != 0:
        raise SystemExit(f"import failed (psql exit {proc.returncode})")


def _feed_status_sql(pack, feed, staleness, count_expr):
    return f"""INSERT INTO knowledge_feed_status
    (feed, source_url, last_fetched_at, source_version, advisory_count, staleness_threshold)
VALUES ({_sql_lit(feed)}, {_sql_lit(pack.get("source_url"))},
        {_sql_lit(pack.get("fetched_at"))}::timestamptz, {_sql_lit(pack.get("source_version"))},
        ({count_expr}), {_sql_lit(staleness)}::interval)
ON CONFLICT (feed) DO UPDATE SET
    source_url = excluded.source_url, last_fetched_at = excluded.last_fetched_at,
    source_version = excluded.source_version, advisory_count = excluded.advisory_count,
    staleness_threshold = excluded.staleness_threshold;"""


# ---------------------------------------------------------------------------
# Corpus: the technique catalogue
# ---------------------------------------------------------------------------
def fetch_corpus(out):
    with _urlopen(CORPUS_URL) as r:
        raw = _read_capped(r, MAX_FEED_BYTES)
    bundle = json.loads(raw.decode("utf-8", "replace"))
    objects = bundle.get("objects") or []

    # STIX ids are internal; the operator-facing identity is the mitre-attack
    # external_id (T1190). Build the map first so `revoked-by` relationships,
    # which are expressed between STIX ids, can be resolved to technique ids.
    stix_to_tid = {}
    for o in objects:
        if o.get("type") != "attack-pattern":
            continue
        for ref in o.get("external_references") or []:
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                stix_to_tid[o["id"]] = ref["external_id"]
                break

    revoked_by = {}
    for o in objects:
        if o.get("type") == "relationship" and o.get("relationship_type") == "revoked-by":
            src, dst = stix_to_tid.get(o.get("source_ref")), stix_to_tid.get(o.get("target_ref"))
            if src and dst:
                revoked_by[src] = dst

    techniques = []
    for o in objects:
        if o.get("type") != "attack-pattern":
            continue
        tid = url = None
        for ref in o.get("external_references") or []:
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                tid, url = ref["external_id"], ref.get("url")
                break
        if not tid:
            continue
        if len(techniques) >= MAX_TECHNIQUES:
            raise SystemExit(f"REFUSED: corpus exceeds the {MAX_TECHNIQUES}-technique bound — refused, not truncated.")
        tactics = [p.get("phase_name") for p in (o.get("kill_chain_phases") or [])
                   if p.get("kill_chain_name") == "mitre-attack" and p.get("phase_name")]
        is_sub = bool(o.get("x_mitre_is_subtechnique"))
        # The parent is carried in the id itself (T1190.001 -> T1190) rather than
        # looked up: the id shape IS the relationship, and deriving it from a
        # second source would give two answers that can disagree.
        parent = tid.split(".")[0] if is_sub and "." in tid else None
        techniques.append({
            "id": _bounded(tid, 32),
            "name": _bounded(o.get("name") or tid),
            "tactics": [_bounded(t, 64) for t in tactics],
            "description": _bounded(o.get("description"), MAX_DESCRIPTION),
            "url": _bounded(url),
            "is_subtechnique": is_sub,
            "parent_id": parent,
            "deprecated": bool(o.get("x_mitre_deprecated")) or bool(o.get("revoked")),
            "revoked_by": revoked_by.get(tid),
        })

    if not techniques:
        raise SystemExit("REFUSED: the corpus yielded no techniques — the STIX shape has changed; do not import an empty catalogue.")

    pack = {
        "feed": "mitre-attack",
        "source_url": CORPUS_URL,
        "source_version": ATTACK_VERSION,
        "fetched_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        # A WHOLE corpus, not a slice. The import's retirement sweep marks every
        # catalogue row absent from the pack as deprecated, which is only a
        # sound inference about a complete bundle -- a partial pack would retire
        # everything it happened not to mention. The flag is what lets the
        # importer tell the two apart instead of assuming.
        "complete": True,
        "techniques": techniques,
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(pack, f)
    subs = sum(1 for t in techniques if t["is_subtechnique"])
    dep = sum(1 for t in techniques if t["deprecated"])
    print(f"fetched {len(techniques)} ATT&CK techniques "
          f"({subs} sub-techniques, {dep} deprecated) at v{ATTACK_VERSION} -> {out}")


def import_corpus(pack_path, db_url):
    _refuse_oversized(pack_path)
    with open(pack_path, encoding="utf-8") as f:
        pack = json.load(f)
    techniques = pack.get("techniques") or []
    if not techniques:
        raise SystemExit("REFUSED: pack carries no techniques — refusing to import an empty catalogue.")
    if len(techniques) > MAX_TECHNIQUES:
        raise SystemExit(f"REFUSED: pack has {len(techniques)} techniques, over the {MAX_TECHNIQUES} bound.")

    tmp = tempfile.mkdtemp(prefix="attack-corpus-")
    try:
        path = os.path.join(tmp, "techniques.csv")
        with open(path, "w", newline="", encoding="utf-8") as cf:
            w = csv.writer(cf)
            for t in techniques:
                # Postgres array literal for text[]; the tactic shortnames are
                # ASCII slugs from a fixed vocabulary, and _bounded already
                # refused anything oversized.
                tactics = "{" + ",".join('"' + s.replace('"', '\\"') + '"' for s in t["tactics"]) + "}"
                w.writerow([t["id"], t["name"], tactics, t.get("description") or "",
                            t.get("url") or "", "t" if t["is_subtechnique"] else "f",
                            t.get("parent_id") or "", "t" if t["deprecated"] else "f",
                            t.get("revoked_by") or ""])
        # RETIREMENT, the half that was missing. ADR-105 requires a technique which
        # disappears from a later corpus to be "retired with its history rather
        # than deleted". The upsert alone cannot do that: it only ever touches
        # rows the pack mentions, so a technique dropped by a new release kept
        # deprecated=false and went on looking current for ever. Measured, not
        # reasoned about -- a corpus with T1040 stripped imported clean and left
        # T1040 sitting in the catalogue unretired.
        #
        # Only ever from a COMPLETE pack, and only ever a flag: nothing is
        # deleted, so a finding that cited the technique keeps its reason.
        if pack.get("complete"):
            retire_sql = """
UPDATE attack_techniques SET deprecated = true, last_fetched_at = excluded_fetched.v
  FROM (SELECT {fetched}::timestamptz AS v) AS excluded_fetched
 WHERE NOT deprecated
   AND technique_id NOT IN (SELECT technique_id FROM _tech);
""".format(fetched=_sql_lit(pack.get("fetched_at")))
        else:
            retire_sql = (
                "-- No retirement sweep: this pack does not declare itself a complete\n"
                "-- corpus, and deprecating every row it fails to mention would retire\n"
                "-- the catalogue on the strength of a partial fetch.\n"
            )
        sql = f"""
\\set ON_ERROR_STOP on
BEGIN;
CREATE TEMP TABLE _tech (
    technique_id text, name text, tactics text, description text, url text,
    is_subtechnique text, parent_id text, deprecated text, revoked_by text
) ON COMMIT DROP;
\\copy _tech FROM '{path}' WITH (FORMAT csv)

INSERT INTO attack_techniques
    (technique_id, name, tactics, description, url, is_subtechnique, parent_id,
     deprecated, revoked_by, attack_version, last_fetched_at)
SELECT technique_id, name, tactics::text[], nullif(description,''), nullif(url,''),
       is_subtechnique::boolean, nullif(parent_id,''), deprecated::boolean,
       nullif(revoked_by,''), {_sql_lit(pack.get("source_version"))},
       {_sql_lit(pack.get("fetched_at"))}::timestamptz
FROM _tech
ON CONFLICT (technique_id) DO UPDATE SET
    name = excluded.name, tactics = excluded.tactics,
    description = excluded.description, url = excluded.url,
    is_subtechnique = excluded.is_subtechnique, parent_id = excluded.parent_id,
    deprecated = excluded.deprecated, revoked_by = excluded.revoked_by,
    attack_version = excluded.attack_version, last_fetched_at = excluded.last_fetched_at;

{retire_sql}
-- The check 0050 deliberately did NOT spell as a foreign key. The curated rule
-- mappings are seeded by a migration and the catalogue arrives later, so the
-- constraint cannot live in the schema -- but a curated technique id that names
-- nothing would otherwise be a join that silently returns no technique, which is
-- indistinguishable downstream from "this rule has no mapping" (ADR-105
-- decision 4 turns on exactly that distinction).
--
-- TWO OUTCOMES, NOT ONE, and the split was found by running the check rather
-- than reading it. A curated id ABSENT FROM THE TABLE is a typo or a corpus from
-- the wrong era: nothing can ever join to it, so refuse. A curated id that is
-- present but newly DEPRECATED is an ordinary ATT&CK upgrade -- the technique is
-- retired, ADR-105 keeps it so old findings still explain themselves, and
-- refusing would block a legitimate corpus bump. That one warns loudly instead,
-- because the curation now points at something retired and a person should
-- revisit it.
DO $$
DECLARE missing text; retired text;
BEGIN
    SELECT string_agg(DISTINCT rt.technique_id, ', ') INTO missing
      FROM rule_techniques rt
     WHERE NOT EXISTS (SELECT 1 FROM attack_techniques at WHERE at.technique_id = rt.technique_id);
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION
            'curated rule mappings name technique(s) absent from this corpus: %. Either a curated id is a typo, or this corpus is not the version the curation was written against (pinned: {ATTACK_VERSION}).',
            missing;
    END IF;

    SELECT string_agg(DISTINCT rt.technique_id, ', ') INTO retired
      FROM rule_techniques rt JOIN attack_techniques at USING (technique_id)
     WHERE at.deprecated;
    IF retired IS NOT NULL THEN
        RAISE WARNING
            'curated rule mappings point at technique(s) this corpus has RETIRED: %. They are kept and still render (ADR-105: a finding that cited one must still explain itself), but the curation should be revisited against the current corpus.',
            retired;
    END IF;
END $$;

{_feed_status_sql(pack, "mitre-attack", ATTACK_STALENESS, "SELECT count(*) FROM attack_techniques")}
COMMIT;
"""
        _run_psql(db_url, sql)
        print(f"imported {len(techniques)} ATT&CK techniques (v{pack.get('source_version')}) from {pack_path}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# Mappings: CVE -> technique, from a published dataset
# ---------------------------------------------------------------------------
def fetch_mappings(out):
    with _urlopen(MAPPINGS_URL) as r:
        raw = _read_capped(r, MAX_FEED_BYTES)
    doc = json.loads(raw.decode("utf-8", "replace"))
    meta = doc.get("metadata") or {}
    got = str(meta.get("attack_version") or "")
    if got != ATTACK_VERSION:
        raise SystemExit(
            f"REFUSED: the mapping dataset declares ATT&CK {got!r}, this pipeline is pinned to "
            f"{ATTACK_VERSION!r}. Mappings authored against a different corpus name techniques the "
            f"catalogue may not hold, or hold under another name. Bump both pins together.")

    rows = []
    for m in doc.get("mapping_objects") or []:
        cve, tid = m.get("capability_id"), m.get("attack_object_id")
        if not cve or not tid:
            continue  # the dataset carries unmapped capabilities; they are not rows here
        if len(rows) >= MAX_MAPPINGS:
            raise SystemExit(f"REFUSED: mapping dataset exceeds the {MAX_MAPPINGS}-row bound — refused, not truncated.")
        rows.append({
            "cve_id": _bounded(cve, 64),
            "technique_id": _bounded(tid, 32),
            # The source's OWN qualifier, carried verbatim. ADR-105 decision 1
            # forbids inventing a confidence, and this is what the source
            # actually publishes in its place.
            "mapping_type": _bounded(m.get("mapping_type") or "unspecified", 64),
            "comments": _bounded(m.get("comments"), MAX_DESCRIPTION),
        })

    if not rows:
        raise SystemExit("REFUSED: the mapping dataset yielded no rows — its shape has changed.")

    pack = {
        "feed": "mitre-attack-cve",
        "source": MAPPING_SOURCE,
        "source_url": MAPPINGS_URL,
        "source_version": MAPPING_VERSION,
        "attack_version": ATTACK_VERSION,
        "fetched_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "mappings": rows,
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(pack, f)
    print(f"fetched {len(rows)} CVE->technique mappings over "
          f"{len({r['cve_id'] for r in rows})} CVEs and {len({r['technique_id'] for r in rows})} techniques "
          f"({MAPPING_SOURCE} {MAPPING_VERSION}, ATT&CK {ATTACK_VERSION}) -> {out}")


def import_mappings(pack_path, db_url):
    _refuse_oversized(pack_path)
    with open(pack_path, encoding="utf-8") as f:
        pack = json.load(f)
    rows = pack.get("mappings") or []
    if not rows:
        raise SystemExit("REFUSED: pack carries no mappings — refusing to import an empty dataset.")
    if len(rows) > MAX_MAPPINGS:
        raise SystemExit(f"REFUSED: pack has {len(rows)} mappings, over the {MAX_MAPPINGS} bound.")

    tmp = tempfile.mkdtemp(prefix="attack-map-")
    try:
        path = os.path.join(tmp, "mappings.csv")
        with open(path, "w", newline="", encoding="utf-8") as cf:
            w = csv.writer(cf)
            for r in rows:
                w.writerow([r["cve_id"], r["technique_id"], r["mapping_type"], r.get("comments") or ""])
        sql = f"""
\\set ON_ERROR_STOP on
BEGIN;
CREATE TEMP TABLE _map (cve_id text, technique_id text, mapping_type text, comments text)
    ON COMMIT DROP;
\\copy _map FROM '{path}' WITH (FORMAT csv)

-- A mapping naming a technique the catalogue does not hold would join to
-- nothing, and "no technique" is the answer ADR-105 decision 4 reserves for "we
-- have no mapping". Refuse rather than store a row that can only ever read as
-- its own opposite.
DO $$
DECLARE missing bigint; sample text;
BEGIN
    SELECT count(DISTINCT m.technique_id),
           string_agg(DISTINCT m.technique_id, ', ' ORDER BY m.technique_id)
      INTO missing, sample
      FROM _map m
     WHERE NOT EXISTS (SELECT 1 FROM attack_techniques at WHERE at.technique_id = m.technique_id);
    IF missing > 0 THEN
        RAISE EXCEPTION
            'the mapping dataset names % technique(s) absent from the catalogue (e.g. %). Import the corpus first (make knowledge-attack-corpus), and check both pins are the same ATT&CK version.',
            missing, left(sample, 200);
    END IF;
END $$;

INSERT INTO cve_techniques
    (cve_id, technique_id, mapping_type, source, source_version, attack_version,
     source_confidence, comments, last_fetched_at)
SELECT cve_id, technique_id, mapping_type,
       {_sql_lit(pack.get("source"))}, {_sql_lit(pack.get("source_version"))},
       {_sql_lit(pack.get("attack_version"))},
       -- NULL, deliberately: this source publishes no confidence, and ADR-105
       -- decision 1 forbids inventing one.
       NULL,
       nullif(comments,''), {_sql_lit(pack.get("fetched_at"))}::timestamptz
FROM _map
ON CONFLICT (cve_id, technique_id, mapping_type) DO UPDATE SET
    source = excluded.source, source_version = excluded.source_version,
    attack_version = excluded.attack_version, comments = excluded.comments,
    last_fetched_at = excluded.last_fetched_at;

-- Coverage, stated rather than implied (ADR-105 decision 4). This is the number
-- that says whether the feature is doing anything on THIS installation, and it
-- is printed at import time so nobody has to go looking for it.
DO $$
DECLARE mapped bigint; known bigint; defs bigint;
BEGIN
    SELECT count(DISTINCT cve_id) INTO mapped FROM cve_techniques;
    SELECT count(*) INTO defs FROM vulnerability_defs;
    SELECT count(DISTINCT vd.cve_id) INTO known
      FROM vulnerability_defs vd JOIN cve_techniques ct ON ct.cve_id = vd.cve_id;
    RAISE NOTICE 'ATT&CK CVE coverage: % of this installation''s % CVE definitions carry a mapping (the dataset maps % CVEs in total).',
        known, defs, mapped;
    IF known = 0 THEN
        RAISE NOTICE 'No ingested CVE is mapped. The published dataset covers CISA KEV (commercial and appliance software); a USN-only advisory set will not intersect it. Findings read "unmapped", which is ADR-105 decision 4 working, not a failure.';
    END IF;
END $$;

{_feed_status_sql(pack, "mitre-attack-cve", ATTACK_STALENESS, "SELECT count(*) FROM cve_techniques")}
COMMIT;
"""
        _run_psql(db_url, sql)
        print(f"imported {len(rows)} CVE->technique mappings from {pack_path}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description="MITRE ATT&CK ingestion (ADR-105)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, needs_db in [("fetch-corpus", False), ("import-corpus", True),
                           ("fetch-mappings", False), ("import-mappings", True)]:
        p = sub.add_parser(name)
        if needs_db:
            p.add_argument("--pack", required=True)
            p.add_argument("--db-url", default=os.environ.get("KNOWLEDGE_IMPORT_DATABASE_URL"))
        else:
            p.add_argument("--out", required=True)
    args = ap.parse_args()

    if args.cmd in ("import-corpus", "import-mappings") and not args.db_url:
        raise SystemExit("--db-url or KNOWLEDGE_IMPORT_DATABASE_URL is required (ADR-063: the import role, never the app role).")

    if args.cmd == "fetch-corpus":
        fetch_corpus(args.out)
    elif args.cmd == "import-corpus":
        import_corpus(args.pack, args.db_url)
    elif args.cmd == "fetch-mappings":
        fetch_mappings(args.out)
    elif args.cmd == "import-mappings":
        import_mappings(args.pack, args.db_url)


if __name__ == "__main__":
    main()
