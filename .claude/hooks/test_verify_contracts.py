#!/usr/bin/env python3
"""Test suite for verify-contracts.py.

Every case performs a REAL write, with a real interpreter, into a real git
repository, and then asks the hook what it noticed. Nothing here inspects a
command string, because the thing under test deliberately does not either -- the
whole point of this half of the guard is that it does not care how the write was
spelled. A test that fed it a fabricated payload would be testing the wrong
object.

ALLOW means exit 0 (the hook saw nothing worth reporting). BLOCK means exit 2
(the hook reports and the message goes back to Claude).

An interpreter that is not installed produces SKIP, not PASS. A missing runtime
must not read as a passing case -- that is how a suite goes quietly green over
coverage it no longer has.

Run:      python3 .claude/hooks/test_verify_contracts.py
Sabotage: CVAP_VERIFY_HOOK=/tmp/mutant.py python3 .claude/hooks/test_verify_contracts.py
          (expected to FAIL -- see the sabotage notes at the bottom of this file)
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
HOOK = pathlib.Path(os.environ.get("CVAP_VERIFY_HOOK") or
                    ROOT / ".claude" / "hooks" / "verify-contracts.py")

ALLOW, BLOCK, SKIP = "ALLOW", "BLOCK", "SKIP"

# --- mutation testing (make mutate) -----------------------------------------
#
# This list is why the suite is worth anything. Running it by hand found three
# real coverage gaps in three sessions — the in-HEAD check, the dedup key, and
# "exactly one line changed" — and in each the existing cases were caught by a
# DIFFERENT check first, so the one under test was never reached.
#
# Adding a check to verify-contracts.py means adding its mutation here.
MUTATION_SUBJECT = ".claude/hooks/verify-contracts.py"
MUTATION_ENV = "CVAP_VERIFY_HOOK"

MUTATIONS = [
    ("reports nothing at all",
     "    if not reportable:\n        return 0",
     "    if True:\n        return 0"),
    ("ADRs are not watched",
     '        elif ADR_RE.match(path):\n            out.append((path, "adr"))\n',
     ""),
    ("dedup keys on the path rather than the content",
     'fresh = [(p, k) for p, k in reportable if "%s:%s" % (p, _fingerprint(p)) not in seen]\n'
     '    if not fresh:\n        return 0\n\n'
     '    for path, _ in reportable:\n'
     '        seen.add("%s:%s" % (path, _fingerprint(path)))',
     'fresh = [(p, k) for p, k in reportable if p not in seen]\n'
     '    if not fresh:\n        return 0\n\n'
     '    for path, _ in reportable:\n'
     '        seen.add(path)'),
    ("an uncommitted draft is treated as frozen",
     "if not path or not _in_head(path):",
     "if not path:"),
    ("the proto escape also excuses ADRs",
     'if kind == "proto" and escaped:',
     "if escaped:"),
    ("supersession permits any edit to the named ADR",
     "    changed = [(b, a) for b, a in zip(before, after) if b != a]\n"
     "    if len(changed) != 1:\n        return False",
     "    changed = [(b, a) for b, a in zip(before, after) if b != a]\n"
     "    if False:\n        return False"),
    ("supersession ignores which ADR was named",
     "        if int(want) != int(have):\n            return False",
     "        if False:\n            return False"),
    ("supersession ignores the line count",
     "    if len(before) != len(after):\n        return False",
     "    if False:\n        return False"),
    ("supersession ignores whether the changed line is the status",
     "    return bool(status.match(was.strip()) and status.match(is_.strip()))",
     "    return True"),
]

PROTO = "proto/cybersentinel/scanpoint/v1/frozen.proto"
ADR = "docs/adr/900-committed.md"
DRAFT = "docs/adr/901-draft.md"
INDEX = "docs/adr/000-index.md"
ORDINARY = "internal/store/jobs.go"

GIT = ["git", "-c", "user.email=t@example.invalid", "-c", "user.name=t"]


def build_repo() -> pathlib.Path:
    """A repository with a committed proto, a committed ADR and a draft."""
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="cvap-verify-"))
    for rel, body in (
        (PROTO, 'syntax = "proto3";\npackage frozen;\n'),
        (ADR, "# ADR-900\n\n**Status:** Accepted\n**Date:** 2026-09-01\n\nBody text that a supersession has no business touching.\n"),
        (INDEX, "| 900 | fixture | Accepted |\n"),
        (ORDINARY, "package store\n"),
    ):
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    for args in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "fixture"]):
        subprocess.run(GIT + ["-C", str(tmp)] + args, check=True, capture_output=True)
    # Written after the commit, so it has no history: a draft.
    (tmp / DRAFT).write_text("# ADR-901\n\n**Status:** Accepted\n")
    return tmp


def reset_repo(repo: pathlib.Path) -> None:
    subprocess.run(GIT + ["-C", str(repo), "checkout", "-q", "--", "."],
                   check=True, capture_output=True)


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


# Each writer takes an absolute path and returns argv that overwrites it.
def py_write(path: str) -> list[str]:
    return ["python3", "-c",
            "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('mutated\\n')", path]


def py_delete(path: str) -> list[str]:
    return ["python3", "-c", "import pathlib,sys; pathlib.Path(sys.argv[1]).unlink()", path]


def perl_write(path: str) -> list[str]:
    return ["perl", "-e", 'open(F, ">", $ARGV[0]); print F "mutated\n"; close F;', path]


def node_write(path: str) -> list[str]:
    return ["node", "-e",
            "require('fs').writeFileSync(process.argv[1],'mutated\\n')", path]


def ruby_write(path: str) -> list[str]:
    return ["ruby", "-e", 'File.write(ARGV[0], "mutated\n")', path]


def sh_write(path: str) -> list[str]:
    return ["bash", "-c", 'printf "mutated\\n" > "$1"', "_", path]


# (name, interpreter-needed, writer, target, env, expected)
CASES: list[tuple[str, str | None, object, str | None, dict, str]] = [
    # --- the bypass that motivated this hook ---
    ("python3 rewrites a committed proto", "python3", py_write, PROTO, {}, BLOCK),
    ("python3 rewrites a committed ADR", "python3", py_write, ADR, {}, BLOCK),
    ("python3 DELETES a committed proto", "python3", py_delete, PROTO, {}, BLOCK),

    # --- other interpreters, none of them enumerated anywhere in the hook ---
    ("node rewrites a committed proto", "node", node_write, PROTO, {}, BLOCK),
    ("node rewrites a committed ADR", "node", node_write, ADR, {}, BLOCK),
    ("perl rewrites a committed ADR", "perl", perl_write, ADR, {}, BLOCK),
    ("ruby rewrites a committed proto", "ruby", ruby_write, PROTO, {}, BLOCK),
    ("bash -c redirects into a committed proto", "bash", sh_write, PROTO, {}, BLOCK),
    ("bash -c redirects into a committed ADR", "bash", sh_write, ADR, {}, BLOCK),

    # --- what must NOT fire ---
    ("an uncommitted ADR is a draft", "python3", py_write, DRAFT, {}, ALLOW),
    ("the ADR index is appendable", "python3", py_write, INDEX, {}, ALLOW),
    ("an ordinary source file", "python3", py_write, ORDINARY, {}, ALLOW),
    ("no write at all", None, None, None, {}, ALLOW),

    # --- the escape hatch reaches proto/ and stops there ---
    ("the escape authorises a proto change", "python3", py_write, PROTO,
     {"CVAP_ALLOW_PROTO_EDIT": "1"}, ALLOW),
    ("the escape does NOT reach a committed ADR", "python3", py_write, ADR,
     {"CVAP_ALLOW_PROTO_EDIT": "1"}, BLOCK),
    ("escape set to something other than 1 does not authorise", "python3", py_write, PROTO,
     {"CVAP_ALLOW_PROTO_EDIT": "0"}, BLOCK),
]


def run_hook(repo: pathlib.Path, state: pathlib.Path, env_overrides: dict) -> int:
    env = {
        "CLAUDE_PROJECT_DIR": str(repo),
        "CVAP_CONTRACT_VERIFY_STATE": str(state),
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }
    env.update(env_overrides)
    proc = subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps({"tool_name": "Bash", "tool_input": {"command": "irrelevant"}}),
        capture_output=True, text=True, env=env,
    )
    return proc.returncode


def code_to_word(code: int) -> str:
    return ALLOW if code == 0 else BLOCK if code == 2 else "exit %d" % code


def main() -> int:
    repo = build_repo()
    tmpstate = pathlib.Path(tempfile.mkdtemp(prefix="cvap-verify-state-"))
    results: list[tuple[str, str, str, bool | None]] = []

    try:
        for i, (name, needs, writer, target, env, want) in enumerate(CASES):
            if needs and not have(needs):
                results.append((name, want, SKIP, None))
                continue
            reset_repo(repo)
            if writer is not None and target is not None:
                subprocess.run(writer(str(repo / target)), check=True, capture_output=True)
            got = code_to_word(run_hook(repo, tmpstate / ("s%d.json" % i), env))
            results.append((name, want, got, got == want))

        # --- the supersession hatch, where the constraint actually lives ---
        #
        # The PreToolUse guard lets the edit through on the variable alone,
        # because it sees a path and not content. This is the half that decides
        # whether what landed was the edit that was authorised.
        #
        # The body case is the one that matters: a hatch that permitted any
        # edit to a named ADR would be a general edit hatch wearing a narrow
        # name, and it is the case a reader is most likely to assume is covered.
        # Reset first: the CASES loop leaves its last mutation in place, and a
        # dirty proto would be reported alongside the ADR — the hook doing
        # exactly its job, failing a case about something else.
        reset_repo(repo)
        adr = repo / ADR
        original = adr.read_text()

        def restore():
            adr.write_text(original)

        # Status only, with the variable naming this ADR: silent.
        restore()
        adr.write_text(original.replace("**Status:** Accepted",
                                        "**Status:** Superseded by ADR-999"))
        got = code_to_word(run_hook(repo, tmpstate / "sup1.json", {"CVAP_SUPERSEDE_ADR": "900"}))
        results.append(("a status-only edit to the named ADR is authorised", ALLOW, got,
                        got == ALLOW))

        # The same edit without the variable: reported.
        got = code_to_word(run_hook(repo, tmpstate / "sup2.json", {}))
        results.append(("the same edit without the variable is reported", BLOCK, got,
                        got == BLOCK))

        # The variable naming a DIFFERENT ADR authorises nothing.
        got = code_to_word(run_hook(repo, tmpstate / "sup3.json", {"CVAP_SUPERSEDE_ADR": "123"}))
        results.append(("the variable naming another ADR authorises nothing", BLOCK, got,
                        got == BLOCK))

        # A BODY edit with the variable set. The case that would turn a narrow
        # hatch into a general one, and the one this suite was sabotaged
        # against — see the notes at the bottom.
        restore()
        adr.write_text(original.replace("**Status:** Accepted",
                                        "**Status:** Superseded by ADR-999")
                       + "\nsmuggled body text\n")
        got = code_to_word(run_hook(repo, tmpstate / "sup4.json", {"CVAP_SUPERSEDE_ADR": "900"}))
        results.append(("a body edit with the variable set is still reported", BLOCK, got,
                        got == BLOCK))

        # Status changed AND a body line changed, with the line count UNCHANGED.
        #
        # The case that reaches the "exactly one line differs" check, and the
        # only one that does: appending smuggled text changes the count, and
        # editing a body line alone fails the status-shape test. Sabotage found
        # this — disabling the one-line check left the suite green, because
        # every existing case was caught by a different guard first. A hatch
        # that let a supersession carry a body edit alongside it would be a
        # general edit hatch that merely looks narrow.
        restore()
        adr.write_text(original
                       .replace("**Status:** Accepted", "**Status:** Superseded by ADR-999")
                       .replace("Body text that a supersession has no business touching.",
                                "Body text quietly rewritten under cover of a supersession."))
        got = code_to_word(run_hook(repo, tmpstate / "sup6.json", {"CVAP_SUPERSEDE_ADR": "900"}))
        results.append(("a status edit smuggling a body change alongside it is reported",
                        BLOCK, got, got == BLOCK))

        # A body edit that leaves the status alone, same line count. Nothing
        # about "only one line changed" should be satisfiable by changing a
        # line that is not the status.
        restore()
        adr.write_text(original.replace("# ADR-900", "# ADR-900 rewritten"))
        got = code_to_word(run_hook(repo, tmpstate / "sup5.json", {"CVAP_SUPERSEDE_ADR": "900"}))
        results.append(("a one-line edit that is not the status is reported", BLOCK, got,
                        got == BLOCK))

        restore()

        # --- a staged file has still never been committed ---
        #
        # This is the only shape that reaches the in-HEAD test. An UNTRACKED
        # draft never appears in `git diff HEAD` at all, so it is exempt without
        # the check doing any work; a staged one does appear, and is still a
        # draft nobody has committed. Sabotage found this gap: removing the
        # in-HEAD check left the whole suite green until this case existed.
        reset_repo(repo)
        staged = "docs/adr/902-staged.md"
        (repo / staged).write_text("# ADR-902\n\n**Status:** Accepted\n")
        subprocess.run(GIT + ["-C", str(repo), "add", staged], check=True, capture_output=True)
        subprocess.run(py_write(str(repo / staged)), check=True, capture_output=True)
        got = code_to_word(run_hook(repo, tmpstate / "staged.json", {}))
        results.append(("a staged but never committed ADR is a draft", ALLOW, got,
                        got == ALLOW))
        subprocess.run(GIT + ["-C", str(repo), "rm", "-q", "-f", "--cached", staged],
                       check=True, capture_output=True)
        (repo / staged).unlink()

        # --- dedup: reported once per distinct content, not once per call ---
        reset_repo(repo)
        shared = tmpstate / "dedup.json"
        subprocess.run(py_write(str(repo / PROTO)), check=True, capture_output=True)
        first = code_to_word(run_hook(repo, shared, {}))
        second = code_to_word(run_hook(repo, shared, {}))
        (repo / PROTO).write_text("a different mutation\n")
        third = code_to_word(run_hook(repo, shared, {}))
        results += [
            ("a change is reported the first time", BLOCK, first, first == BLOCK),
            ("the same change is not reported twice", ALLOW, second, second == ALLOW),
            ("a DIFFERENT change to the same file reports again", BLOCK, third, third == BLOCK),
        ]

        # --- committing the change is what clears it ---
        reset_repo(repo)
        subprocess.run(py_write(str(repo / PROTO)), check=True, capture_output=True)
        subprocess.run(GIT + ["-C", str(repo), "add", "-A"], check=True, capture_output=True)
        subprocess.run(GIT + ["-C", str(repo), "commit", "-q", "-m", "deliberate"],
                       check=True, capture_output=True)
        after = code_to_word(run_hook(repo, tmpstate / "committed.json", {}))
        results.append(("committing the change clears the report", ALLOW, after, after == ALLOW))

        # --- fail quiet, not false, where the question cannot be asked ---
        plain = pathlib.Path(tempfile.mkdtemp(prefix="cvap-verify-norepo-"))
        (plain / "proto").mkdir()
        norepo = code_to_word(run_hook(plain, tmpstate / "norepo.json", {}))
        results.append(("outside a repository the detector is silent", ALLOW, norepo,
                        norepo == ALLOW))
        shutil.rmtree(plain, ignore_errors=True)

        # A ROOT below the toplevel: git would resolve paths against the wrong
        # base and see nothing. Silent is right, and the PreToolUse guard fails
        # CLOSED in the same situation, so the pair still refuses.
        nested = code_to_word(run_hook(repo / "proto", tmpstate / "nested.json", {}))
        results.append(("a project dir below the toplevel is silent", ALLOW, nested,
                        nested == ALLOW))
    finally:
        shutil.rmtree(repo, ignore_errors=True)
        shutil.rmtree(tmpstate, ignore_errors=True)

    width = max(len(n) for n, _, _, _ in results)
    print(f"{'#':>3}  {'case'.ljust(width)}  {'want':<5}  {'got':<5}  result")
    print("-" * (width + 30))
    failures = skipped = 0
    for i, (name, want, got, ok) in enumerate(results, 1):
        if ok is None:
            skipped += 1
            verdict = "SKIP (interpreter not installed)"
        else:
            failures += not ok
            verdict = "PASS" if ok else "FAIL"
        print(f"{i:>3}  {name.ljust(width)}  {want:<5}  {got:<5}  {verdict}")
    print("-" * (width + 30))
    print(f"{len(results) - failures - skipped}/{len(results) - skipped} passed"
          + (f", {skipped} skipped" if skipped else ""))
    return 1 if failures else 0


# SABOTAGE NOTES
# --------------
# This suite is only worth what it catches, so it was checked by breaking the
# hook on purpose and confirming it goes red. Point CVAP_VERIFY_HOOK at a mutant
# to repeat any of these:
#
#   always return 0                 -> every BLOCK case fails
#   drop the ADR branch             -> the ADR cases fail, proto still passes
#   dedup on path alone             -> "a DIFFERENT change ... reports again" fails
#   drop the _in_head check         -> "an uncommitted ADR is a draft" fails
#   let the escape cover ADRs too   -> "the escape does NOT reach a committed ADR" fails
#   diff against a snapshot, not HEAD, taken after the write -> every BLOCK case fails

if __name__ == "__main__":
    sys.exit(main())
