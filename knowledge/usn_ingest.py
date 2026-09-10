#!/usr/bin/env python3
"""Ubuntu USN advisory ingestion — Phase 3.2 (ADR-014, ADR-019, ADR-030, ADR-063).

Python, per ADR-001 (Go for the platform, Python for knowledge pipelines). The
comparison itself is NOT here: an advisory says "fixed in 1:4.7p1-8ubuntu1.3" and
Go decides whether an installed version satisfies it, with the dpkg comparator
(ADR-062). USN versions are dpkg-format, so every fixed package this pipeline
writes carries comparator='dpkg' in the row (advisory_fixed_packages.comparator),
which is how the Go matcher knows which comparator to use.

Two separable steps, because ADR-019 requires an offline import path for
air-gapped deployments:

    fetch   (online, scheduled): pull USN -> a normalized advisory PACK (JSON)
                                 with provenance (feed, url, fetched-at, etag).
    import  (offline, idempotent): read a pack -> upsert the knowledge tables via
                                 psql as cvap_knowledge_import_login (ADR-063),
                                 through CSV + \\copy into temp staging so a
                                 hostile feed's strings are read as data, never SQL.

An air-gapped site runs `import` only, on a pack carried in. The two are wired to
a schedule by `make knowledge-usn` / cron; nothing here assumes it runs online.
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
import urllib.parse
import urllib.request

FEED = "ubuntu-usn"
BASE = "https://ubuntu.com/security/notices.json"

# The feed is hostile input (ADR: a vendor JSON is attacker-controlled like a
# banner). These bounds are refusals, not truncations: a truncated advisory set
# imports PARTIAL coverage, which is a silent false negative — the exact failure
# P3.1 was ordered first to avoid. So at the cap the whole fetch is refused.
MAX_FEED_BYTES = 64 * 1024 * 1024  # generous vs the ~real per-query size; refuses a DoS-sized body
MAX_NOTICES = 5000
MAX_FIELD = 4096
MAX_PKGS_PER_ADVISORY = 20000
MAX_CVES_PER_ADVISORY = 4096  # raised from 512 (S39): current aggregate USNs
# (e.g. resolute USN-8727-1 lists 547 CVEs) legitimately exceed 512. Raised
# deliberately rather than dropping CVEs silently, which the 512 refusal itself
# instructed. Still bounded so a malformed feed cannot be unbounded.

# Past this age, matching against the feed is under-reporting, so it is STALE.
# Stored in the data (knowledge_feed_status.staleness_threshold) so the API
# answers "stale?" and the panel renders the answer.
STALENESS_THRESHOLD = "7 days"


def _bounded(v, n=MAX_FIELD):
    if v is None:
        return None
    s = str(v)
    if len(s) > n:
        raise SystemExit(f"REFUSED: a feed field exceeds {n} bytes ({s[:60]!r}...). "
                         "Unbounded input from a vendor document is not imported.")
    return s


def _read_capped(resp, cap):
    buf = bytearray()
    while True:
        chunk = resp.read(65536)
        if not chunk:
            break
        buf += chunk
        if len(buf) > cap:
            raise SystemExit(
                f"REFUSED: feed body exceeds {cap} bytes. A truncated feed imports a "
                "partial advisory set — silent false negatives — so the whole fetch is "
                "refused, not truncated (ADR-014, ADR-060). Narrow the query or raise the "
                "cap deliberately.")
    return bytes(buf)


def fetch(release, package, limit, out, offset=0):
    # The USN API filters by release/limit/order/offset only; package is filtered
    # client-side below (the API 422s on an unknown query param).
    params = {"release": release, "order": "newest", "limit": str(min(max(limit, 1), 20))}
    if offset:
        params["offset"] = str(offset)
    url = BASE + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "CVAP-knowledge/usn (ADR-019)"})
    with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 (fixed https host)
        etag = r.headers.get("ETag")
        raw = _read_capped(r, MAX_FEED_BYTES)
    doc = json.loads(raw)
    notices = doc.get("notices") or []
    if len(notices) > MAX_NOTICES:
        raise SystemExit(f"REFUSED: {len(notices)} notices exceeds the {MAX_NOTICES} bound.")

    advisories = []
    for n in notices:
        rp = n.get("release_packages") or {}
        if package and not any(
            e.get("name") == package or (e.get("name") or "").startswith(package)
            for entries in rp.values() for e in (entries or [])
        ):
            continue
        pkgs = []
        for rel, entries in rp.items():
            rel = _bounded(rel, 64)
            for e in (entries or []):
                if len(pkgs) >= MAX_PKGS_PER_ADVISORY:
                    raise SystemExit("REFUSED: advisory package list exceeds bound.")
                pkgs.append({
                    "release": rel,
                    "name": _bounded(e.get("name"), 256),
                    "version": _bounded(e.get("version"), 256),
                    "is_source": bool(e.get("is_source")),
                })
        cve_ids = n.get("cves_ids") or n.get("cves") or []
        # Refuse, do not truncate: silently dropping CVEs past a cap is the exact
        # silent-false-negative this module's bounds exist to prevent (a truncated
        # CVE list under-reports what an advisory covers). Consistent with the
        # notice/package caps above, which raise rather than slice.
        if len(cve_ids) > MAX_CVES_PER_ADVISORY:
            raise SystemExit(
                f"REFUSED: advisory {n.get('id')!r} lists {len(cve_ids)} CVEs, over the "
                f"{MAX_CVES_PER_ADVISORY} bound. A truncated CVE list under-reports coverage; "
                "raise the bound deliberately rather than dropping CVEs silently.")
        advisories.append({
            "ref": _bounded(n.get("id"), 128),
            "vendor": "ubuntu",
            "cves": [_bounded(c, 64) for c in cve_ids],
            "issued_at": _bounded(n.get("published"), 64),
            "packages": pkgs,
        })

    pack = {
        "feed": FEED,
        "source_url": url,
        "fetched_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source_etag": etag,
        "staleness_threshold": STALENESS_THRESHOLD,
        "advisories": advisories,
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(pack, f, indent=1)
    print(f"fetched {len(advisories)} advisories from {url} -> {out} "
          f"(etag={etag}, {sum(len(a['packages']) for a in advisories)} fixed packages)")


def import_pack(pack_path, db_url):
    # The import path trusts less than fetch (a carried-in pack for an air-gapped
    # site may have any provenance, ADR-019), so cap the pack file the same way
    # fetch caps the feed body — a truncated/oversized pack is refused, not read
    # into memory whole.
    size = os.path.getsize(pack_path)
    if size > MAX_FEED_BYTES:
        raise SystemExit(
            f"REFUSED: pack {pack_path} is {size} bytes, over the {MAX_FEED_BYTES} bound. "
            "An oversized pack is refused rather than loaded into memory whole.")
    with open(pack_path, encoding="utf-8") as f:
        pack = json.load(f)
    advisories = pack.get("advisories") or []

    tmp = tempfile.mkdtemp(prefix="usn-import-")
    try:
        adv_csv = os.path.join(tmp, "adv.csv")
        pkg_csv = os.path.join(tmp, "pkg.csv")
        cve_csv = os.path.join(tmp, "cve.csv")

        # Only source packages carry the canonical fixed version; binaries repeat
        # it, so importing sources avoids a fan-out of duplicate
        # (advisory,release,name).
        with open(adv_csv, "w", newline="", encoding="utf-8") as af, \
             open(pkg_csv, "w", newline="", encoding="utf-8") as pf, \
             open(cve_csv, "w", newline="", encoding="utf-8") as cf:
            aw, pw, cw = csv.writer(af), csv.writer(pf), csv.writer(cf)
            for a in advisories:
                ref = a["ref"]
                aw.writerow([ref, a.get("vendor") or "ubuntu", a.get("issued_at") or ""])
                for c in a.get("cves") or []:
                    cw.writerow([ref, c])
                for p in a.get("packages") or []:
                    if not p.get("is_source"):
                        continue
                    pw.writerow([ref, p["release"], p["name"], p["version"]])

        sql = f"""
\\set ON_ERROR_STOP on
BEGIN;
CREATE TEMP TABLE _adv (ref text, vendor text, issued text) ON COMMIT DROP;
CREATE TEMP TABLE _pkg (ref text, release text, name text, version text) ON COMMIT DROP;
CREATE TEMP TABLE _cve (ref text, cve text) ON COMMIT DROP;
\\copy _adv FROM '{adv_csv}' WITH (FORMAT csv)
\\copy _pkg FROM '{pkg_csv}' WITH (FORMAT csv)
\\copy _cve FROM '{cve_csv}' WITH (FORMAT csv)

-- Advisory: one row per USN. distro_release NULL — a USN spans releases; the
-- per-release detail lives in advisory_fixed_packages.
INSERT INTO vendor_advisories (advisory_ref, vendor, issued_at)
SELECT ref, vendor, nullif(issued,'')::timestamptz FROM _adv
ON CONFLICT (advisory_ref) DO UPDATE SET vendor = excluded.vendor, issued_at = excluded.issued_at;

-- CVEs referenced by the advisory. Title defaults to the id — USN gives no
-- per-CVE title, and title is NOT NULL.
INSERT INTO vulnerability_defs (cve_id, title)
SELECT DISTINCT cve, cve FROM _cve
ON CONFLICT (cve_id) DO NOTHING;

INSERT INTO advisory_vuln_map (advisory_id, vuln_def_id)
SELECT va.advisory_id, vd.vuln_def_id
FROM _cve c JOIN vendor_advisories va ON va.advisory_ref = c.ref
           JOIN vulnerability_defs vd ON vd.cve_id = c.cve
ON CONFLICT DO NOTHING;

-- Fixed packages: the matchable authority. comparator is 'dpkg' — USN versions
-- are dpkg-format, and the Go matcher reads this column to know (ADR-062).
-- DISTINCT ON collapses duplicate (advisory,release,package) rows to one BEFORE
-- the insert. The source-only filter above was assumed to make these unique, but
-- real jammy USNs list a source package twice for one release (pocket variants),
-- and Postgres refuses an ON CONFLICT DO UPDATE that would touch the same key twice
-- in one statement ("cannot affect row a second time"). One deterministic row per
-- key (highest version string) is kept; the versions are near-always identical, so
-- this only removes the crash, not real coverage (S39, found importing current USNs).
INSERT INTO advisory_fixed_packages (advisory_id, distro_release, package_name, fixed_version, comparator)
SELECT DISTINCT ON (va.advisory_id, p.release, p.name)
       va.advisory_id, p.release, p.name, p.version, 'dpkg'::version_comparator
FROM _pkg p JOIN vendor_advisories va ON va.advisory_ref = p.ref
ORDER BY va.advisory_id, p.release, p.name, p.version DESC
ON CONFLICT (advisory_id, distro_release, package_name)
   DO UPDATE SET fixed_version = excluded.fixed_version, comparator = excluded.comparator;

-- Provenance + freshness, threshold stored in the data.
INSERT INTO knowledge_feed_status (feed, source_url, last_fetched_at, source_etag, advisory_count, staleness_threshold)
VALUES ('{pack.get("feed", FEED)}', {_sql_lit(pack.get("source_url"))},
        {_sql_lit(pack.get("fetched_at"))}::timestamptz, {_sql_lit(pack.get("source_etag"))},
        (SELECT count(*) FROM vendor_advisories),
        {_sql_lit(pack.get("staleness_threshold") or STALENESS_THRESHOLD)}::interval)
ON CONFLICT (feed) DO UPDATE SET
    source_url = excluded.source_url, last_fetched_at = excluded.last_fetched_at,
    source_etag = excluded.source_etag, advisory_count = excluded.advisory_count,
    staleness_threshold = excluded.staleness_threshold;
COMMIT;
"""
        proc = subprocess.run(["psql", db_url, "-v", "ON_ERROR_STOP=1", "-q"],
                              input=sql, text=True, capture_output=True)
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        if proc.returncode != 0:
            raise SystemExit(f"import failed (psql exit {proc.returncode})")
        print(f"imported {len(advisories)} advisories from {pack_path}")
    finally:
        # The CSVs hold advisory content, not secrets, but a per-run temp dir that
        # is never removed accumulates in /tmp across every scheduled import.
        shutil.rmtree(tmp, ignore_errors=True)


def _sql_lit(v):
    """A SQL string literal for a PROVENANCE value (feed/url/etag/timestamp) —
    these come from the pack we wrote, not from advisory content, but quote them
    anyway so a crafted pack cannot inject through the metadata line."""
    if v is None:
        return "NULL"
    return "'" + str(v).replace("'", "''") + "'"


RELEASES_URL = "https://ubuntu.com/security/releases.json"
MAX_RELEASES = 500


def _date10(v):
    """The YYYY-MM-DD of an ISO timestamp the feed returns ('2008-04-24T00:00:00'),
    or None. The coverage window is a date, not a moment."""
    if not v:
        return None
    s = _bounded(v, 32)
    return s[:10] if s else None


def fetch_releases(out):
    """Online: the release support/EOL/ESM dates -> a coverage pack. The coverage
    boundary is DATA from the feed (B29), not a constant in code."""
    req = urllib.request.Request(RELEASES_URL, headers={"User-Agent": "CVAP-knowledge/usn (ADR-019)"})
    with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 (fixed https host)
        raw = _read_capped(r, MAX_FEED_BYTES)
    doc = json.loads(raw)
    rels = doc.get("releases") or []
    if len(rels) > MAX_RELEASES:
        raise SystemExit(f"REFUSED: {len(rels)} releases exceeds the {MAX_RELEASES} bound.")
    releases = []
    for rel in rels:
        codename = _bounded(rel.get("codename"), 64)
        if not codename or codename == "upstream":
            continue  # 'upstream' is a sentinel row with null dates, not a release
        releases.append({
            "codename": codename,
            "release_date": _date10(rel.get("release_date")),
            "support_expires": _date10(rel.get("support_expires")),
            "esm_expires": _date10(rel.get("esm_expires")),
        })
    pack = {
        "feed": FEED,
        "source_url": RELEASES_URL,
        "fetched_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "releases": releases,
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(pack, f, indent=1)
    print(f"fetched {len(releases)} release coverage rows from {RELEASES_URL} -> {out}")


def import_releases(pack_path, db_url):
    """Offline: a coverage pack -> release_coverage (B29). Same injection-safe path
    as the advisory import: CSV + \\copy into a temp staging table, then upsert."""
    size = os.path.getsize(pack_path)
    if size > MAX_FEED_BYTES:
        raise SystemExit(f"REFUSED: pack {pack_path} is {size} bytes, over the {MAX_FEED_BYTES} bound.")
    with open(pack_path, encoding="utf-8") as f:
        pack = json.load(f)
    feed = pack.get("feed", FEED)
    fetched_at = pack.get("fetched_at")
    releases = pack.get("releases") or []

    tmp = tempfile.mkdtemp(prefix="usn-releases-")
    try:
        csv_path = os.path.join(tmp, "rel.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as cf:
            w = csv.writer(cf)
            for rel in releases:
                rd = rel.get("release_date")
                se = rel.get("support_expires")
                esm = rel.get("esm_expires")
                # 'feed-degenerate': the feed gave only the release date (its
                # placeholder for releases predating ESM tracking), so the true
                # coverage end is unknown from the feed — but the release is still
                # clearly EOL and the out-of-coverage decision (esm < now) holds.
                degenerate = (not esm) or (rd and esm <= rd)
                source = "feed-degenerate" if degenerate else "feed"
                w.writerow([feed, rel["codename"], rd or "", se or "", esm or "", source])

        sql = f"""
\\set ON_ERROR_STOP on
BEGIN;
CREATE TEMP TABLE _rc (feed text, distro_release text, release_date text,
                       support_expires text, esm_expires text, coverage_source text) ON COMMIT DROP;
\\copy _rc FROM '{csv_path}' WITH (FORMAT csv)
INSERT INTO release_coverage
    (feed, distro_release, release_date, support_expires, esm_expires, coverage_source, last_fetched_at)
SELECT feed, distro_release,
       nullif(release_date,'')::date, nullif(support_expires,'')::date, nullif(esm_expires,'')::date,
       coverage_source, {_sql_lit(fetched_at)}::timestamptz
FROM _rc
ON CONFLICT (feed, distro_release) DO UPDATE SET
    release_date = excluded.release_date, support_expires = excluded.support_expires,
    esm_expires = excluded.esm_expires, coverage_source = excluded.coverage_source,
    last_fetched_at = excluded.last_fetched_at;
COMMIT;
"""
        proc = subprocess.run(["psql", db_url, "-v", "ON_ERROR_STOP=1", "-q"],
                              input=sql, text=True, capture_output=True)
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        if proc.returncode != 0:
            raise SystemExit(f"import failed (psql exit {proc.returncode})")
        print(f"imported {len(releases)} release coverage rows from {pack_path}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description="Ubuntu USN advisory ingestion (P3.2)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch", help="online: USN -> advisory pack")
    f.add_argument("--release", required=True, help="Ubuntu release codename, e.g. hardy, jammy")
    f.add_argument("--package", help="restrict to advisories touching this source package")
    f.add_argument("--limit", type=int, default=10)
    f.add_argument("--offset", type=int, default=0)
    f.add_argument("--out", required=True)
    i = sub.add_parser("import", help="offline: advisory pack -> knowledge tables")
    i.add_argument("--pack", required=True)
    i.add_argument("--db-url", default=os.environ.get("KNOWLEDGE_IMPORT_DATABASE_URL"),
                   help="cvap_knowledge_import_login connection string")
    fr = sub.add_parser("fetch-releases", help="online: release EOL/ESM dates -> coverage pack (B29)")
    fr.add_argument("--out", required=True)
    ir = sub.add_parser("import-releases", help="offline: coverage pack -> release_coverage (B29)")
    ir.add_argument("--pack", required=True)
    ir.add_argument("--db-url", default=os.environ.get("KNOWLEDGE_IMPORT_DATABASE_URL"),
                    help="cvap_knowledge_import_login connection string")
    args = ap.parse_args()
    if args.cmd == "fetch":
        fetch(args.release, args.package, args.limit, args.out, args.offset)
    elif args.cmd == "fetch-releases":
        fetch_releases(args.out)
    elif args.cmd == "import-releases":
        if not args.db_url:
            raise SystemExit("import-releases: --db-url or KNOWLEDGE_IMPORT_DATABASE_URL required")
        import_releases(args.pack, args.db_url)
    else:
        if not args.db_url:
            raise SystemExit("import: --db-url or KNOWLEDGE_IMPORT_DATABASE_URL required")
        import_pack(args.pack, args.db_url)


if __name__ == "__main__":
    main()
