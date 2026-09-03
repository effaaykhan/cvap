#!/usr/bin/env python3
"""Mutation testing for this repository's guard scripts.

A test suite that has never failed proves nothing. Every guard here has a case
table, and a case table can be green over a check it never reaches — which is
not hypothetical: running these mutations by hand found three real coverage gaps
in three consecutive sessions, and in every one of them each existing case was
caught by a DIFFERENT check first, so the one under test was never exercised.

  * verify-contracts' in-HEAD test had no case at all, because an untracked
    draft never appears in `git diff HEAD` and so never reached it.
  * Its "exactly one line changed" test had none either: one case appended a
    line and was caught by the line-count check, the other edited a line before
    the status and was caught by the shape check.
  * Its dedup key was covered only by accident.

Run by hand, that discipline lapses. This makes it a build step.

HOW IT WORKS

Each suite declares three things next to itself:

    MUTATION_SUBJECT   the script it tests, relative to the repository root
    MUTATION_ENV       the environment variable that points it at a mutant
    MUTATIONS          [(name, old, new), ...]

For each mutation this copies the subject, applies the replacement, runs the
suite against the copy, and requires the suite to FAIL. A mutation that survives
is reported by name, and the name is the check nothing exercises.

The mutation list living beside the suite is the point: adding a check means
adding the mutation that proves the check is reached, in the same file, in the
same diff.

An anchor that no longer matches is also a failure. A mutation that cannot be
applied is a mutation that stopped testing anything, and silently skipping it
would be the exact failure this script exists to catch.

Run: python3 .claude/hooks/mutate.py   (or `make mutate`)
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]

# The suites that declare mutations. Others may be added as they grow one; a
# suite without the three attributes is reported rather than skipped, because a
# suite that quietly opts out is how this stops covering anything.
SUITES = [
    ".claude/hooks/test_protect_contracts.py",
    ".claude/hooks/test_verify_contracts.py",
    ".github/scripts/test_check_secret_logging.py",
]


def load(path: pathlib.Path):
    spec = importlib.util.spec_from_file_location("suite_" + path.stem, path)
    mod = importlib.util.module_from_spec(spec)
    # Import only; a suite must not run its cases on import.
    spec.loader.exec_module(mod)
    return mod


def run_suite(suite: pathlib.Path, env_var: str, subject: pathlib.Path) -> bool:
    """True when the suite PASSES against this subject."""
    env = dict(os.environ)
    env[env_var] = str(subject)
    proc = subprocess.run(
        [sys.executable, str(suite)], capture_output=True, text=True, env=env,
        cwd=str(ROOT),
    )
    return proc.returncode == 0


def main() -> int:
    failures = 0
    total = 0
    width = 0
    rows: list[tuple[str, str, str]] = []

    for rel in SUITES:
        suite = ROOT / rel
        mod = load(suite)

        missing = [a for a in ("MUTATION_SUBJECT", "MUTATION_ENV", "MUTATIONS")
                   if not hasattr(mod, a)]
        if missing:
            rows.append((rel, "NO MUTATIONS", "declares none of: " + ", ".join(missing)))
            failures += 1
            continue

        subject = ROOT / mod.MUTATION_SUBJECT
        original = subject.read_text(encoding="utf-8")

        # The suite must pass unmutated, or every result below is meaningless.
        if not run_suite(suite, mod.MUTATION_ENV, subject):
            rows.append((rel, "BASELINE RED", "the suite fails against its own subject"))
            failures += 1
            continue

        for name, old, new in mod.MUTATIONS:
            total += 1
            label = "%s :: %s" % (pathlib.Path(rel).stem, name)
            width = max(width, len(label))

            if original.count(old) != 1:
                rows.append((label, "ANCHOR LOST",
                             "matched %d times; the mutation tests nothing"
                             % original.count(old)))
                failures += 1
                continue

            with tempfile.NamedTemporaryFile(
                "w", suffix=subject.suffix, delete=False, encoding="utf-8"
            ) as fh:
                fh.write(original.replace(old, new))
                mutant = pathlib.Path(fh.name)
            try:
                passed = run_suite(suite, mod.MUTATION_ENV, mutant)
            finally:
                mutant.unlink(missing_ok=True)

            if passed:
                rows.append((label, "SURVIVED",
                             "no case exercises the check this mutation removes"))
                failures += 1
            else:
                rows.append((label, "killed", ""))

    width = max(width, max((len(r[0]) for r in rows), default=10))
    print(f"{'mutation':<{width}}  {'result':<12}  note")
    print("-" * (width + 60))
    for label, result, note in rows:
        print(f"{label:<{width}}  {result:<12}  {note}")
    print("-" * (width + 60))

    if failures:
        print(f"{failures} of {total} mutation(s) not killed. A surviving mutation names a "
              f"check no case reaches; add the case, do not delete the mutation.")
        return 1
    print(f"all {total} mutations killed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
