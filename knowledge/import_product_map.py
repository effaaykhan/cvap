#!/usr/bin/env python3
"""Import the product->package map into the knowledge plane (P3.3, ADR-064).

The map (knowledge/product_packages.json) is content, not code (ADR-048): release
resolution reads it to turn an observed service Product into the Ubuntu package
name(s) the advisory keyspace uses. This loads it into the product_packages table
as cvap_knowledge_import (ADR-063), the same offline, injection-safe path the USN
importer uses: values reach the DB via CSV + \\copy into a TEMP staging table,
never string-built SQL.

Full-sync, not additive: the file is the whole truth, so a mapping deleted from
the file is deleted from the table (DELETE + reload in one transaction). A partial
map would leave a stale product->package association that silently mis-scopes a
band search — the same silent-wrong the USN importer refuses truncation to avoid.
"""

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
import tempfile

MAX_FILE_BYTES = 4 * 1024 * 1024  # the map is small; a larger file is refused, not read whole
MAX_ROWS = 100000


def import_map(path, db_url):
    size = os.path.getsize(path)
    if size > MAX_FILE_BYTES:
        raise SystemExit(f"REFUSED: {path} is {size} bytes, over the {MAX_FILE_BYTES} bound.")
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    mapping = doc.get("map") or {}

    rows = []
    for product, packages in mapping.items():
        if not isinstance(packages, list):
            raise SystemExit(f"REFUSED: value for {product!r} is not a list of package names.")
        for pkg in packages:
            if len(rows) >= MAX_ROWS:
                raise SystemExit(f"REFUSED: product map exceeds {MAX_ROWS} rows.")
            rows.append((str(product), str(pkg)))

    tmp = tempfile.mkdtemp(prefix="product-map-")
    try:
        csv_path = os.path.join(tmp, "map.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as cf:
            csv.writer(cf).writerows(rows)
        sql = f"""
\\set ON_ERROR_STOP on
BEGIN;
CREATE TEMP TABLE _map (product text, package_name text) ON COMMIT DROP;
\\copy _map FROM '{csv_path}' WITH (FORMAT csv)
DELETE FROM product_packages;
INSERT INTO product_packages (product, package_name)
SELECT DISTINCT product, package_name FROM _map;
COMMIT;
"""
        proc = subprocess.run(["psql", db_url, "-v", "ON_ERROR_STOP=1", "-q"],
                              input=sql, text=True, capture_output=True)
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        if proc.returncode != 0:
            raise SystemExit(f"import failed (psql exit {proc.returncode})")
        print(f"imported {len(rows)} product->package rows from {path}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description="Import the product->package map (P3.3, ADR-064)")
    ap.add_argument("--file", default="knowledge/product_packages.json")
    ap.add_argument("--db-url", default=os.environ.get("KNOWLEDGE_IMPORT_DATABASE_URL"),
                    help="cvap_knowledge_import_login connection string")
    args = ap.parse_args()
    if not args.db_url:
        raise SystemExit("import: --db-url or KNOWLEDGE_IMPORT_DATABASE_URL required")
    import_map(args.file, args.db_url)


if __name__ == "__main__":
    main()
