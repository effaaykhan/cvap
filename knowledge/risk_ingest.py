#!/usr/bin/env python3
"""CISA KEV + FIRST EPSS ingestion — Phase 3.4 (ADR-069, ADR-063, ADR-019).

Two risk feeds that prioritise the finding set. KEV is ~1700 known-exploited CVEs;
EPSS is a daily probability for ~370k CVEs. Same shape as knowledge/usn_ingest.py:
fetch (online) → a normalized pack (JSON, with provenance) → import (offline,
idempotent) via CSV + \\copy into TEMP staging, as cvap_knowledge_import (ADR-063).

Absence is not evidence (ADR-069): a CVE not in the KEV pack is unlisted (not
known-unexploited); a CVE not in the EPSS pack is unscored (not probability 0).
Neither import writes a "safe" sentinel — absence is the absence of a row.
"""

import argparse
import csv
import datetime
import gzip
import json
import os
import shutil
import subprocess
import sys
import tempfile

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

# Hostile-input bounds, refusals not truncations (ADR-069). EPSS is every published
# CVE, so USN's 5000-notice cap would bite; raised deliberately with headroom, and a
# larger body is REFUSED — a truncated risk feed is silent under-reporting.
MAX_FEED_BYTES = 64 * 1024 * 1024        # compressed/raw body cap (KEV ~1.7MB, EPSS gz ~2.6MB)
MAX_DECOMPRESSED_BYTES = 128 * 1024 * 1024  # gunzip bomb guard (EPSS ~11MB uncompressed)
MAX_KEV_ENTRIES = 50000                  # KEV ~1700
MAX_EPSS_ROWS = 1_000_000                # EPSS ~370k; refuse above this
MAX_FIELD = 4096

KEV_STALENESS = "7 days"
EPSS_STALENESS = "2 days"                 # EPSS updates daily — tighter than USN


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
    req = urllib.request.Request(url, headers={"User-Agent": "CVAP-knowledge/risk (ADR-019)"})
    return urllib.request.urlopen(req, timeout=60)  # noqa: S310 (fixed https hosts)


# ---------------------------------------------------------------------------
# KEV
# ---------------------------------------------------------------------------
def fetch_kev(out):
    with _urlopen(KEV_URL) as r:
        raw = _read_capped(r, MAX_FEED_BYTES)
    doc = json.loads(raw)
    vulns = doc.get("vulnerabilities") or []
    if len(vulns) > MAX_KEV_ENTRIES:
        raise SystemExit(f"REFUSED: {len(vulns)} KEV entries exceeds the {MAX_KEV_ENTRIES} bound.")
    entries = []
    for v in vulns:
        cve = _bounded(v.get("cveID"), 64)
        if not cve:
            continue
        entries.append({
            "cve": cve,
            "date_added": _bounded(v.get("dateAdded"), 32),
            "known_ransomware": (str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"),
            "source": _bounded(v.get("vendorProject"), 256),
        })
    pack = {
        "feed": "cisa-kev",
        "source_url": KEV_URL,
        "fetched_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_version": _bounded(doc.get("catalogVersion"), 64),
        "entries": entries,
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(pack, f)
    print(f"fetched {len(entries)} KEV entries -> {out}")


def import_kev(pack_path, db_url):
    _refuse_oversized(pack_path)
    with open(pack_path, encoding="utf-8") as f:
        pack = json.load(f)
    entries = pack.get("entries") or []
    tmp = tempfile.mkdtemp(prefix="kev-import-")
    try:
        path = os.path.join(tmp, "kev.csv")
        with open(path, "w", newline="", encoding="utf-8") as cf:
            w = csv.writer(cf)
            for e in entries:
                w.writerow([e["cve"], e.get("date_added") or "",
                            "t" if e.get("known_ransomware") else "f", e.get("source") or ""])
        sql = f"""
\\set ON_ERROR_STOP on
BEGIN;
CREATE TEMP TABLE _kev (cve_id text, date_added text, known_ransomware text, source text) ON COMMIT DROP;
\\copy _kev FROM '{path}' WITH (FORMAT csv)
INSERT INTO kev (cve_id, date_added, known_ransomware, source, last_fetched_at)
SELECT cve_id, nullif(date_added,'')::date, known_ransomware::boolean, nullif(source,''),
       {_sql_lit(pack.get("fetched_at"))}::timestamptz
FROM _kev
ON CONFLICT (cve_id) DO UPDATE SET
    date_added = excluded.date_added, known_ransomware = excluded.known_ransomware,
    source = excluded.source, last_fetched_at = excluded.last_fetched_at;
{_feed_status_sql(pack, "cisa-kev", KEV_STALENESS, "SELECT count(*) FROM kev")}
COMMIT;
"""
        _run_psql(db_url, sql)
        print(f"imported {len(entries)} KEV entries from {pack_path}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# EPSS
# ---------------------------------------------------------------------------
def fetch_epss(out):
    with _urlopen(EPSS_URL) as r:
        raw = _read_capped(r, MAX_FEED_BYTES)
    # Gunzip with an output bound (decompression-bomb guard).
    with gzip.GzipFile(fileobj=__import__("io").BytesIO(raw)) as gz:
        data = gz.read(MAX_DECOMPRESSED_BYTES + 1)
    if len(data) > MAX_DECOMPRESSED_BYTES:
        raise SystemExit(f"REFUSED: EPSS decompresses to over {MAX_DECOMPRESSED_BYTES} bytes — refused (gzip bomb guard).")
    text = data.decode("utf-8", "replace")
    lines = text.splitlines()
    score_date = None
    scores = []
    reader = csv.reader(lines)
    for row in reader:
        if not row:
            continue
        if row[0].startswith("#"):  # e.g. "#model_version:...,score_date:2026-09-08T..."
            for part in row:
                if "score_date:" in part:
                    score_date = _bounded(part.split("score_date:", 1)[1], 40)
            continue
        if row[0] == "cve":         # header
            continue
        if len(row) < 2:
            continue
        if len(scores) >= MAX_EPSS_ROWS:
            raise SystemExit(f"REFUSED: EPSS exceeds the {MAX_EPSS_ROWS}-row bound — refused, not truncated (ADR-069).")
        scores.append([_bounded(row[0], 64), _bounded(row[1], 16), _bounded(row[2], 16) if len(row) > 2 else ""])
    pack = {
        "feed": "first-epss",
        "source_url": EPSS_URL,
        "fetched_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "score_date": (score_date[:10] if score_date else None),
        "scores": scores,
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(pack, f)
    print(f"fetched {len(scores)} EPSS scores (score_date={pack['score_date']}) -> {out}")


def import_epss(pack_path, db_url):
    _refuse_oversized(pack_path)
    with open(pack_path, encoding="utf-8") as f:
        pack = json.load(f)
    scores = pack.get("scores") or []
    if len(scores) > MAX_EPSS_ROWS:
        raise SystemExit(f"REFUSED: pack has {len(scores)} EPSS rows, over the {MAX_EPSS_ROWS} bound.")
    scored_at = pack.get("score_date")
    tmp = tempfile.mkdtemp(prefix="epss-import-")
    try:
        path = os.path.join(tmp, "epss.csv")
        with open(path, "w", newline="", encoding="utf-8") as cf:
            w = csv.writer(cf)
            for s in scores:
                w.writerow([s[0], s[1], s[2] if len(s) > 2 else ""])
        sql = f"""
\\set ON_ERROR_STOP on
BEGIN;
CREATE TEMP TABLE _epss (cve_id text, score text, percentile text) ON COMMIT DROP;
\\copy _epss FROM '{path}' WITH (FORMAT csv)
INSERT INTO epss (cve_id, score, percentile, scored_at, last_fetched_at)
SELECT cve_id, score::numeric, nullif(percentile,'')::numeric, {_sql_lit(scored_at)}::date,
       {_sql_lit(pack.get("fetched_at"))}::timestamptz
FROM _epss
ON CONFLICT (cve_id) DO UPDATE SET
    score = excluded.score, percentile = excluded.percentile,
    scored_at = excluded.scored_at, last_fetched_at = excluded.last_fetched_at;
{_feed_status_sql(pack, "first-epss", EPSS_STALENESS, "SELECT count(*) FROM epss")}
COMMIT;
"""
        _run_psql(db_url, sql)
        print(f"imported {len(scores)} EPSS scores from {pack_path}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
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


def main():
    ap = argparse.ArgumentParser(description="CISA KEV + FIRST EPSS ingestion (P3.4)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, needs_db in [("fetch-kev", False), ("import-kev", True),
                           ("fetch-epss", False), ("import-epss", True)]:
        p = sub.add_parser(name)
        if needs_db:
            p.add_argument("--pack", required=True)
            p.add_argument("--db-url", default=os.environ.get("KNOWLEDGE_IMPORT_DATABASE_URL"))
        else:
            p.add_argument("--out", required=True)
    args = ap.parse_args()
    if args.cmd in ("import-kev", "import-epss") and not args.db_url:
        raise SystemExit(f"{args.cmd}: --db-url or KNOWLEDGE_IMPORT_DATABASE_URL required")
    if args.cmd == "fetch-kev":
        fetch_kev(args.out)
    elif args.cmd == "import-kev":
        import_kev(args.pack, args.db_url)
    elif args.cmd == "fetch-epss":
        fetch_epss(args.out)
    elif args.cmd == "import-epss":
        import_epss(args.pack, args.db_url)


if __name__ == "__main__":
    main()
