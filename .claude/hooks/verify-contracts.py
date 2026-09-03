#!/usr/bin/env python3
"""
CVAP PostToolUse verifier for frozen contract files.

protect-contracts.py asks "does this command look like a write to a frozen
file". This asks "did a frozen file change". They are not the same question, and
the second one is the only one that cannot be worked around.

WHY THIS EXISTS
---------------
The PreToolUse guard enumerates ways to write a file: redirects, tee, sed -i,
mv, cp, rm, dd. That list is a guess about how a write will be spelled, and the
guess was wrong in the most ordinary way possible -- a `python3 - <<'PY'` heredoc
calling pathlib.write_text goes straight through it, and that is the single most
common editing method in this repository. The guard was blind to its own most
likely bypass for as long as it existed.

Extending the enumeration was considered and rejected. Detecting interpreters --
python3, perl, ruby, node, sh -c -- is the same enumeration game one level up:
`uv run`, `env python`, `go run`, `./tool.py`, a make target, xargs, a compiled
binary. The list never closes, and every miss is silent. Worse, it fires on
reading: `cat proto/x.proto | python3 -` mentions a protected path in a command
that only reads it. For proto/ a false block costs one environment variable, but
committed ADRs have no override by design, so a false block there has no way
through at all -- and a guard people cannot get past is a guard people delete.

So: stop guessing at the spelling. Hash the outcome.

WHAT IT COMPARES AGAINST
------------------------
HEAD, not a snapshot taken before the tool ran.

A pre-call snapshot would attribute a change to the exact call that made it,
which is tidier. It also races: Claude Code runs tool calls in parallel, and two
overlapping Bash calls can interleave their snapshots such that one call's write
is already present in the other's baseline. That miss is a false NEGATIVE, which
for a guard is the one failure mode that matters. HEAD cannot race with anything.

The cost is that this reports "a frozen file differs from HEAD" rather than "this
call changed it". That turns out to be the more useful statement anyway, because
there is no legitimate steady state where a committed frozen file is dirty: the
PreToolUse guard blocks every sanctioned route, so a difference means either
CVAP_ALLOW_PROTO_EDIT authorised it or something got past. Reporting until it is
committed or reverted is correct rather than noisy.

DETECTION, NOT PREVENTION
-------------------------
The write has already landed when this runs. That is the honest trade: it cannot
stop the edit, and it cannot be evaded by how the edit was made. git makes it
recoverable, and the message below carries the revert command, so the loss is one
`git checkout` -- against silence on a bypass nobody detected.

NOISE
-----
A given change is reported once. The dedup key is the path plus the CONTENT of
the file, so a second, different edit to the same file reports again. The state
file is best-effort: if it is lost, the report repeats, which is the fail-loud
direction. Nothing about correctness depends on it.

Exit 2 returns the message to Claude. Exit 0 is silence.

Run the tests: python3 .claude/hooks/test_verify_contracts.py
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(os.environ.get("CLAUDE_PROJECT_DIR", ".")).resolve()

ESCAPE_VAR = "CVAP_ALLOW_PROTO_EDIT"

# The supersession hatch, named by ADR number: CVAP_SUPERSEDE_ADR=035.
#
# The PreToolUse guard lets the edit through on the strength of this variable
# alone, because it sees a path and not content. THIS hook is where the
# constraint actually lives: it diffs the result against HEAD and stays quiet
# only if the Status line is the only thing that moved. A body edit with the
# variable set is reported exactly like an unauthorised one, which is the reason
# the pair is safe to open at all.
SUPERSEDE_VAR = "CVAP_SUPERSEDE_ADR"

# Best-effort, and deliberately outside the repository: this is scratch state,
# not something to commit or to have show up in git status.
STATE_PATH = os.environ.get("CVAP_CONTRACT_VERIFY_STATE") or os.path.join(
    "/tmp", "cvap-contract-verify-%s.json" % hashlib.sha256(str(ROOT).encode()).hexdigest()[:16]
)

PROTO_RE = re.compile(r"^proto/.*\.proto$")
ADR_RE = re.compile(r"^docs/adr/(?!000-index\.md$).*\.md$")


def _git(*args: str, text: bool = True) -> subprocess.CompletedProcess | None:
    """Run git at ROOT. None means the question could not be asked."""
    try:
        return subprocess.run(
            ["git", "-C", str(ROOT), *args],
            capture_output=True, text=text, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _repo_is_answerable() -> bool:
    """ROOT must BE the repository toplevel, with a commit in it.

    Same requirement protect-contracts.py has, for the same reason: git resolves
    `-C <dir>` by walking up, so a ROOT below the toplevel would have every
    relative path resolved against the wrong base.

    Unanswerable is treated as "nothing to report" rather than as an alarm. This
    half of the pair is a detector, and a detector that cannot run should be
    quiet rather than crying wolf on every call -- the PreToolUse guard already
    fails CLOSED in exactly this case, refusing edits outright, so the pair still
    refuses rather than silently allowing.
    """
    top = _git("rev-parse", "--show-toplevel")
    if top is None or top.returncode != 0:
        return False
    if pathlib.Path(top.stdout.strip()).resolve() != ROOT:
        return False
    head = _git("rev-parse", "--verify", "--quiet", "HEAD")
    return head is not None and head.returncode == 0


def _in_head(relative: str) -> bool:
    """Whether this path is committed. An uncommitted file is not frozen.

    A brand-new .proto breaks no deployed scan point, and an ADR with no commit
    is a draft its author may still fix. Both mirror protect-contracts.py.
    """
    found = _git("cat-file", "-e", "HEAD:" + relative)
    return found is not None and found.returncode == 0


def changed_protected_paths() -> list[tuple[str, str]]:
    """Protected paths differing from HEAD, as (path, kind)."""
    diff = _git("diff", "--name-only", "HEAD", "--", "proto", "docs/adr")
    if diff is None or diff.returncode != 0:
        return []

    out: list[tuple[str, str]] = []
    for line in diff.stdout.splitlines():
        path = line.strip()
        if not path or not _in_head(path):
            continue
        if PROTO_RE.match(path):
            out.append((path, "proto"))
        elif ADR_RE.match(path):
            out.append((path, "adr"))
    return out


def _adr_number(path: str) -> str | None:
    m = re.match(r"^(\d{3})-", pathlib.PurePosixPath(path).name)
    return m.group(1) if m else None


def _authorised_supersession(path: str) -> bool:
    """Whether this change is a status-only edit the operator authorised.

    Three things must hold, and each rules out a way of turning a narrow hatch
    into a general one:

      * the operator named THIS ADR in the environment;
      * the file still has the same number of lines as HEAD, so nothing was
        added or removed;
      * the only line that differs is the Status line, and it still reads as a
        Status line.

    Anything else -- a body edit, a reordering, a second ADR touched under one
    variable -- falls through and is reported like any other change to a frozen
    file. The write has already landed either way; the report is what reaches a
    human, so the question is only whether this one was asked for.
    """
    want = os.environ.get(SUPERSEDE_VAR, "").strip()
    have = _adr_number(path)
    if not want or have is None:
        return False
    try:
        if int(want) != int(have):
            return False
    except ValueError:
        return False

    head = _git("show", "HEAD:" + path)
    if head is None or head.returncode != 0:
        return False
    try:
        now = (ROOT / path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False

    before = head.stdout.splitlines()
    after = now.splitlines()
    if len(before) != len(after):
        return False

    changed = [(b, a) for b, a in zip(before, after) if b != a]
    if len(changed) != 1:
        return False

    was, is_ = changed[0]
    status = re.compile(r"^\*\*Status:\*\*", re.IGNORECASE)
    return bool(status.match(was.strip()) and status.match(is_.strip()))


def _fingerprint(path: str) -> str:
    """Content of the file as it stands, or a marker when it is gone."""
    try:
        return hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
    except OSError:
        return "absent"


def _load_state() -> set[str]:
    try:
        with open(STATE_PATH, encoding="utf-8") as fh:
            return set(json.load(fh))
    except (OSError, ValueError):
        return set()


def _save_state(seen: set[str]) -> None:
    try:
        with open(STATE_PATH, "w", encoding="utf-8") as fh:
            json.dump(sorted(seen), fh)
    except OSError:
        pass  # Best effort. Losing it repeats a report, which is fail-loud.


def main() -> int:
    try:
        json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        pass  # The payload is not consulted. The filesystem is the input.

    if not _repo_is_answerable():
        return 0

    escaped = os.environ.get(ESCAPE_VAR, "0") == "1"

    reportable = []
    for path, kind in changed_protected_paths():
        # The escape hatch covers proto/ and nothing else, exactly as the
        # PreToolUse guard does.
        if kind == "proto" and escaped:
            continue
        # A committed ADR has one narrow override: an operator-named
        # supersession, and only if the Status line is all that moved.
        if kind == "adr" and _authorised_supersession(path):
            continue
        reportable.append((path, kind))

    if not reportable:
        return 0

    seen = _load_state()
    fresh = [(p, k) for p, k in reportable if "%s:%s" % (p, _fingerprint(p)) not in seen]
    if not fresh:
        return 0

    for path, _ in reportable:
        seen.add("%s:%s" % (path, _fingerprint(path)))
    _save_state(seen)

    lines = [
        "FROZEN FILE CHANGED: a contract file differs from HEAD.",
        "",
        "This is the PostToolUse check, so the write has already landed. It does not",
        "care how the file was written -- an interpreter, a redirect, an editor, a",
        "compiled binary -- only that a frozen file is no longer what was committed.",
        "",
    ]
    for path, kind in fresh:
        gone = not (ROOT / path).exists()
        what = "DELETED" if gone else "modified"
        lines.append("  %s  %s" % (what.ljust(8), path))
        if kind == "proto":
            lines.append("            proto/ is additive-only within a major version (ADR-022).")
        else:
            lines.append("            Accepted ADRs are superseded, never edited (ADR-029 aside,")
            lines.append("            which is an enumeration its own text says to append to).")
            if os.environ.get(SUPERSEDE_VAR, "").strip():
                lines.append("            " + SUPERSEDE_VAR + " is set, and this change is NOT a")
                lines.append("            status-only edit to the ADR it names. The hatch permits")
                lines.append("            setting Status and nothing else.")
    lines += [
        "",
        "If this was not deliberate, revert it:",
        "",
        "    git checkout -- " + " ".join(p for p, _ in fresh),
        "",
        "If it WAS deliberate: a proto change needs CVAP_ALLOW_PROTO_EDIT=1 in this",
        "hook's environment. A committed ADR needs a superseding ADR — and the one",
        "edit that supersession requires, setting Status to \"Superseded by ADR-NNN\",",
        "needs CVAP_SUPERSEDE_ADR=<nnn> naming it.",
        "Committing the change clears this, which is the point -- a frozen file should",
        "not sit modified in a working tree with nobody having decided to keep it.",
    ]
    print("\n".join(lines), file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
