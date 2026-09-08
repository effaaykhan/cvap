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
import json
import os
import re
import pathlib
import shlex
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

# Go suites that declare mutations in a comment block beside the tests.
#
# The Python suites are pointed at a mutant FILE through an environment
# variable, which a compiled language cannot do. Go's `-overlay` is built for
# exactly this: a JSON map from a real path to a replacement, applied at compile
# time, so the working tree is never modified and there is nothing to restore if
# this is interrupted.
#
# A suite here without a mutation block is reported rather than skipped, same as
# for Python — a suite that quietly opts out is how this stops covering
# anything.
GO_SUITES = [
    "internal/control/credential/phc_test.go",
    # bootstrap verifies its own login path; the mutation inverts the credential
    # check so a wrong password would pass — "a bootstrap that cannot log in has
    # not bootstrapped".
    "cmd/cvap-cli/bootstrap_test.go",
    # --domain is required (no localhost default), and tenant set-domain audits
    # the privileged change — the two mutations restore the old bug and drop the
    # audit.
    "cmd/cvap-cli/tenant_test.go",
    # The load test's coarse/precise gate split — each half sabotaged
    # independently, DB-free so the mutation runs without a seeded 10k corpus.
    "test/load/gate_test.go",
    "internal/control/api/oidc_ssrf_test.go",
    "internal/control/api/oidc_test.go",
    "internal/dispatch/scope_conformance_test.go",
    "internal/scanpoint/scope_conformance_test.go",
    "internal/scanpoint/safetymode_test.go",
    "internal/engines/enginerate/ratebudget_test.go",
    "internal/engines/fingerprint/tls_test.go",
    "internal/engines/fingerprint/payload_test.go",
    "internal/scanpoint/corpus_test.go",
    "internal/domain/identity_test.go",
    # OS attribution (B21, ADR-061): the service precedence and the "ignored"
    # provenance role — one mutation reverses precedence, the other stops a
    # disagreeing hint being recorded as overruled.
    "internal/domain/attribution_test.go",
    # P3.1 version comparators (ADR-059 P3.1, ADR-014). dpkg semantics — the
    # tilde ordering and numeric comparison, the two subtlest bits, each mutated;
    # a wrong dpkg compare is a silent false negative.
    "internal/version/dpkg_test.go",
    "internal/rules/evaluators_test.go",
    "internal/control/api/api_read_test.go",
    "internal/control/api/handlers_scan_gate_test.go",
    # The distributed fault-injection matrix (§6.4). Each fault case declares the
    # sabotage its assertion must kill, so the matrix cannot pass vacuously. The
    # e2e entries run real processes, so their mutations are slower than the rest;
    # they are here rather than only under `make e2e` because a sabotage nothing
    # verifies is the vacuous gate this matrix exists to refuse.
    "internal/store/fault_completion_integration_test.go",
    "internal/store/fault_clock_integration_test.go",
    "test/e2e/fault_completion_e2e_test.go",
    # F2's logic sabotage is unit-layer (checkEpoch runs inside the cvap-core
    # binary the e2e harness builds separately, which -overlay cannot reach); the
    # F2 e2e test is the end-to-end observation and carries no mutation. F4 also
    # declares its resumption-vs-duplicate sabotage in ingest_test.go.
    "internal/dispatch/ingest_test.go",
    # F6a (buffer saturation reports HARD) and F6b (Core assigns nothing on HARD).
    "internal/scanpoint/fault_backpressure_test.go",
    "internal/dispatch/dispatch_test.go",
    # F5 (a resumed upload restarts from the last acked chunk, not from zero).
    "internal/scanpoint/fault_resume_test.go",
    # F6×F5 (sustained rejection keeps the buffer and loses nothing) — the compose
    # that surfaced the RETRY_LATER-on-chunk-0 data-loss fix in submit.go.
    "internal/scanpoint/fault_backpressure_buffer_test.go",
    # Shutdown waits for results to be enqueued, not just for the engine to be
    # reaped — an in-process harness over the real shutdown path.
    "internal/scanpoint/fault_shutdown_test.go",
]

# The declaration shape, in comments beside the tests:
#
#   // mutate:subject internal/control/api/oidc_client.go
#   // mutate:test    ./internal/control/api/ -run TestA|TestB
#   // mutate:case    drop the translated-form extraction
#   // mutate:old     candidates = append(candidates, target.TranslatedV4s(ip)...)
#   // mutate:new     _ = target.TranslatedV4s
#
# subject and test are declared once; case/old/new repeat. Mutations are
# single-line by construction, which is a real constraint and the right one: a
# mutation that needs a paragraph is usually testing that the code compiles.
GO_DIRECTIVE = re.compile(r"^\s*//\s*mutate:(subject|test|case|old|new)\s+(.*?)\s*$")


def parse_go_suite(path: pathlib.Path):
    """(test_args, [(name, subject, old, new)]) or (None, reason).

    mutate:subject may be declared more than once and applies to the cases that
    follow it, because one suite legitimately covers checks in two files — the
    OIDC tests exercise both oidc.go and the session issuance in
    handlers_auth.go, and splitting them into two suites to satisfy the format
    would put the mutation somewhere other than beside the test that kills it.
    """
    subject = test_args = None
    cases: list[tuple[str, str, str, str]] = []
    pending: dict[str, str] = {}

    for line in path.read_text(encoding="utf-8").splitlines():
        m = GO_DIRECTIVE.match(line)
        if not m:
            continue
        key, value = m.group(1), m.group(2)
        if key == "subject":
            subject = value
        elif key == "test":
            test_args = value
        else:
            pending[key] = value
            if {"case", "old", "new"} <= pending.keys():
                if subject is None:
                    return None, "a mutate:case appears before any mutate:subject"
                cases.append((pending["case"], subject, pending["old"], pending["new"]))
                pending = {}

    if test_args is None:
        return None, "no mutate:test declared"
    if not cases:
        return None, "declares no mutate:case"
    return test_args, cases


def run_go_suite(test_args: str, overlay: pathlib.Path | None) -> tuple[bool, int]:
    """(passed, tests_that_actually_ran).

    ============================================================================
    A SKIPPED suite passes, and a mutation it does not run always survives.
    ============================================================================

    Most of these suites need CVAP_TEST_DATABASE_URL and call t.Skip without it.
    `go test` then exits 0, so the baseline looked green and every mutant looked
    green too — nine mutations "survived" on a tree where all of them are killed,
    purely because `make ci` did not export the database URL. That is the
    silently-passing gate this repository keeps finding, one level below the gate
    that exists to find it.

    So the count of tests that actually ran is returned alongside the exit
    status, and a baseline that ran nothing is reported rather than trusted.
    """
    # -timeout, because a mutant that makes the code HANG is a normal outcome —
    # removing a cancellation check does exactly that — and without a bound it
    # burns the default ten minutes and then prints no result lines, which this
    # driver reads as "ran no tests" rather than as killed. CI found that; a
    # local run of the single affected test did not, because the hang was in a
    # different test in the same binary.
    cmd = [os.environ.get("GO", "go"), "test", "-count=1", "-v", "-timeout", "120s"]
    if overlay is not None:
        cmd.append("-overlay=" + str(overlay))
    cmd += shlex.split(test_args)
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(ROOT),
                          env=dict(os.environ))
    ran = sum(1 for line in proc.stdout.splitlines()
              if line.startswith("--- PASS:") or line.startswith("--- FAIL:"))
    return proc.returncode == 0, ran


def go_mutations(rows: list) -> tuple[int, int]:
    """Run every Go suite's mutations. Returns (failures, total)."""
    failures = total = 0

    for rel in GO_SUITES:
        suite = ROOT / rel
        test_args, cases = parse_go_suite(suite)
        if test_args is None:
            rows.append((rel, "NO MUTATIONS", cases))
            failures += 1
            continue

        baseline, ran = run_go_suite(test_args, None)
        if ran == 0:
            rows.append((rel, "BASELINE EMPTY",
                         "the suite ran no tests — every mutation would survive. "
                         "Set CVAP_TEST_DATABASE_URL (make up)."))
            failures += 1
            continue
        if not baseline:
            rows.append((rel, "BASELINE RED", "the suite fails against its own subject"))
            failures += 1
            continue

        for name, subject_rel, old, new in cases:
            total += 1
            label = "%s :: %s" % (pathlib.Path(rel).stem, name)
            subject = ROOT / subject_rel
            original = subject.read_text(encoding="utf-8")

            if original.count(old) != 1:
                rows.append((label, "ANCHOR LOST",
                             "matched %d times in %s; the mutation tests nothing"
                             % (original.count(old), subject_rel)))
                failures += 1
                continue

            with tempfile.TemporaryDirectory() as tmp:
                mutant = pathlib.Path(tmp) / subject.name
                mutant.write_text(original.replace(old, new), encoding="utf-8")
                overlay = pathlib.Path(tmp) / "overlay.json"
                overlay.write_text(json.dumps(
                    {"Replace": {str(subject): str(mutant)}}), encoding="utf-8")
                passed, mutantRan = run_go_suite(test_args, overlay)

            if mutantRan == 0:
                rows.append((label, "MUTANT EMPTY",
                             "the mutant ran no tests — it probably does not compile, "
                             "so it tests nothing. Reformulate it to compile."))
                failures += 1
                continue
            if passed:
                rows.append((label, "SURVIVED",
                             "no case exercises the check this mutation removes"))
                failures += 1
            else:
                rows.append((label, "killed", ""))

    return failures, total


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

    goFailures, goTotal = go_mutations(rows)
    failures += goFailures
    total += goTotal

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
