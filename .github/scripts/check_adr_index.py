#!/usr/bin/env python3
"""Every ADR has an index row, and every index row has an ADR.

============================================================================
adr-compliance found 048, 049 and 050 missing from the index, and nothing
else would have. This is that check, made mechanical.
============================================================================

The index (docs/adr/000-index.md) is the registry adr-compliance and the
new-ADR flow read. An ADR absent from it is effectively unrecorded — the exact
drift that let three committed ADRs go unlisted across as many sessions. A row
with no file is the opposite drift: a decision referenced that was never
written, or renumbered and not cleaned up.

The check is symmetric on purpose. A one-directional check (files must be
indexed) would miss a stale row; the pair is what makes the index and the
directory prove each other.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
ADR_DIR = ROOT / "docs" / "adr"
INDEX = ADR_DIR / "000-index.md"

# 000 is the index itself. It does not carry a row for itself, and requiring one
# would be a check asserting a thing nobody wants true.
INDEX_NUMBER = "000"


def adr_files():
    """Numbers of every NNN-*.md in the directory, except the index."""
    nums = {}
    for p in sorted(ADR_DIR.glob("*.md")):
        m = re.match(r"^(\d{3})-", p.name)
        if not m:
            # A .md in the ADR directory that is not numbered is either the
            # index or a stray. The index is expected; anything else is worth
            # naming rather than silently skipping.
            if p.name != "000-index.md" and p.name.lower() != "readme.md":
                print(f"adr-index: {p.name} is in docs/adr/ and is not a numbered ADR "
                      "(and is not the index or a README)", file=sys.stderr)
            continue
        if m.group(1) == INDEX_NUMBER:
            continue
        nums.setdefault(m.group(1), p.name)
    return nums


def index_rows():
    """Numbers that appear as a leading table cell `| NNN |` in the index."""
    if not INDEX.exists():
        print(f"adr-index: {INDEX} does not exist", file=sys.stderr)
        sys.exit(1)
    rows = {}
    for line in INDEX.read_text().splitlines():
        m = re.match(r"^\|\s*(\d{3})\s*\|", line)
        if m:
            rows[m.group(1)] = line.strip()
    return rows


def main():
    files = adr_files()
    rows = index_rows()

    problems = []
    for num, name in sorted(files.items()):
        if num not in rows:
            problems.append(f"  ADR {num} ({name}) has no row in 000-index.md")
    for num in sorted(rows):
        if num not in files:
            problems.append(f"  index row {num} names an ADR with no docs/adr/{num}-*.md file")

    if problems:
        print("adr-index: FAILED", file=sys.stderr)
        for p in problems:
            print(p, file=sys.stderr)
        print("\nEvery docs/adr/NNN-*.md needs a `| NNN | ... |` row in 000-index.md, "
              "and every row needs a file.", file=sys.stderr)
        return 1

    print(f"adr-index OK: {len(files)} ADRs, all indexed; {len(rows)} rows, all backed by a file.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
