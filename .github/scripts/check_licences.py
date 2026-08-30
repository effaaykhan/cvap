#!/usr/bin/env python3
"""Fail the build on GPL or AGPL dependencies.

ADR-025 draws the build-versus-consume line and permits consuming commodity
infrastructure. It does not permit consuming it under a licence that would
oblige us to publish the analysis that is the product.

This deliberately does NOT use a general licence classifier. Those tools bucket
by category — "forbidden", "restricted" — and their restricted set includes
LGPL and MPL, which ADR-025 permits. A check that fails on dependencies the
ADR allows gets weakened by whoever hits it at 2am, rather than debugged. So
the deny list here is exactly the ADR's: GPL and AGPL, with LGPL explicitly
allowed.

Reads the module cache for every dependency in the build list and scans its
licence files. Zero dependencies is a pass, which is the correct answer for an
empty tree.
"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys

LICENCE_FILENAMES = re.compile(
    r"^(LICEN[CS]E|COPYING|LEGAL|NOTICE)(\.(md|txt|rst))?$", re.IGNORECASE
)

# Ordered: LGPL is checked first so it is not caught by the bare GPL pattern.
ALLOWED_LESSER = re.compile(
    r"GNU LESSER GENERAL PUBLIC LICENSE|\bLGPL[- ]?[23]", re.IGNORECASE
)
DENIED = [
    ("AGPL", re.compile(r"GNU AFFERO GENERAL PUBLIC LICENSE|\bAGPL[- ]?3", re.IGNORECASE)),
    ("GPL", re.compile(r"GNU GENERAL PUBLIC LICENSE|(?<!L)(?<!A)\bGPL[- ]?[23]", re.IGNORECASE)),
]


def module_dirs() -> list[tuple[str, pathlib.Path]]:
    """Every dependency module in the build list, with its cache directory."""
    proc = subprocess.run(
        ["go", "list", "-deps", "-json", "-mod=mod", "./..."],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        raise SystemExit("go list failed")

    seen: dict[str, pathlib.Path] = {}
    decoder = json.JSONDecoder()
    text = proc.stdout.strip()
    idx = 0
    while idx < len(text):
        while idx < len(text) and text[idx].isspace():
            idx += 1
        if idx >= len(text):
            break
        obj, end = decoder.raw_decode(text, idx)
        idx = end
        mod = obj.get("Module")
        if not mod or mod.get("Main"):
            continue
        path, directory = mod.get("Path"), mod.get("Dir")
        if path and directory and path not in seen:
            seen[path] = pathlib.Path(directory)
    return sorted(seen.items())


def scan(directory: pathlib.Path) -> list[tuple[str, pathlib.Path]]:
    hits: list[tuple[str, pathlib.Path]] = []
    for path in directory.rglob("*"):
        if not path.is_file() or not LICENCE_FILENAMES.match(path.name):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if ALLOWED_LESSER.search(text):
            continue
        for label, pattern in DENIED:
            if pattern.search(text):
                hits.append((label, path))
                break
    return hits


def main() -> int:
    mods = module_dirs()
    if not mods:
        print("No third-party dependencies. Licence check passes trivially.")
        return 0

    failures: list[str] = []
    for path, directory in mods:
        for label, licence_path in scan(directory):
            failures.append(f"  {path}: {label} detected in {licence_path.name}")

    if failures:
        print(
            f"Licence check FAILED — GPL/AGPL is out of bounds under ADR-025 "
            f"({len(failures)} finding(s)):",
            file=sys.stderr,
        )
        for line in failures:
            print(line, file=sys.stderr)
        print(
            "\nReplace the dependency, or supersede ADR-025 with an ADR that argues "
            "for the change. Do not weaken this check.",
            file=sys.stderr,
        )
        return 1

    print(f"Licence check OK: {len(mods)} dependency module(s), no GPL/AGPL.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
