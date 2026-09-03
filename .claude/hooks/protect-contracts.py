#!/usr/bin/env python3
"""
CVAP PreToolUse guard for frozen contract files.

Two things in this repository are frozen:

  proto/**/*.proto   The wire contract. Additive-only within a major version
                     (ADR-022), because scan points in customer networks run
                     months-old builds and a removed or renumbered field is a
                     fleet-wide outage in a network we cannot observe.

  docs/adr/*.md      Accepted decisions. They are superseded, never edited, so
                     that a future reader can see what was decided and what was
                     rejected. 000-index.md is the exception: it is the table of
                     contents and has to be appended to.

The guard covers two write paths, because there are two ways to write a file.

  file_path mode  Edit / Write / NotebookEdit hand the hook a tool_input.file_path.
  command mode    Bash hands the hook a tool_input.command and no path at all.

The second one is why this script exists in its current form. The previous
version read tool_input.file_path only. Adding Bash to the settings.json matcher
without teaching it to read a command would have produced a guard that looks
extended and protects nothing: every Bash call would present an empty path and
exit 0. A heredoc is the most natural way to write a proto file from a shell,
and it was the one path straight through the guard.

Exit 2 blocks the tool call and returns the message to Claude.

UNCOMMITTED ADRs ARE STILL DRAFTS
--------------------------------
An ADR is frozen by being COMMITTED, not by carrying the word Accepted. A file
with no commit in HEAD is a draft: nobody else has read it, nothing links to it,
and no decision has been settled by it. Its author fixing a typo before the
commit lands is not a later session rewriting a settled decision, which is the
only thing this half of the guard was built to stop.

The gap was found the way these things are: a session wrote an ADR, a reviewer
in the same session found a wording error in it, and the guard refused the
author's own correction -- with no override, because Accepted ADRs deliberately
have none. Supersession is not a sane answer for a document that has never
existed outside one working tree.

So: no commit in HEAD, editable. One commit in HEAD, frozen, and supersession is
the only route from then on. The check is `git cat-file -e HEAD:<path>` and it
fails CLOSED -- no git, no repository, no HEAD, or any other doubt, and the file
is treated as committed.

Note this is a property of the FILE's history, not of the session. A draft that
survives to a commit is frozen for everyone including the person who wrote it,
which is the moment other people can start relying on it.

ESCAPE HATCH
------------
A genuinely additive proto change, or the commit that establishes the baseline,
sets CVAP_ALLOW_PROTO_EDIT=1 in the hook's own environment. That is the only
form accepted.

It applies to proto/ ONLY. A committed Accepted ADR has no override of any kind
-- see below.

An earlier version of this hook also honoured an inline
`CVAP_ALLOW_PROTO_EDIT=1 cmd` assignment written into the Bash command, on the
grounds that it left the override visible in the transcript beside the write it
authorised. That optimises the wrong property. An override reachable from
inside the command string is reachable by anything that composes commands,
including a future session that hits this guard and routes around it rather
than asking. Requiring the environment means the bypass needs a human to act,
which is the entire point of a freeze. Visibility does not help if nobody is
reading.

SUPERSEDING A COMMITTED ADR
--------------------------
A committed Accepted ADR is superseded, not edited -- and supersession itself
requires one edit to it: setting its status to "Superseded by ADR-NNN". This
guard forbade exactly the edit its own error message prescribes, so the remedy
was unreachable through it and two supersessions went in past the pattern
matcher instead. A guard that forbids its own remedy teaches people to route
around it, which costs more than the rule was worth.

CVAP_SUPERSEDE_ADR=<nnn> in the hook's environment permits an edit to ADR-nnn and
to nothing else. Same rule as CVAP_ALLOW_PROTO_EDIT: the ENVIRONMENT only, never
an assignment inside a command, because an override anything composing a command
can write into is one anything composing a command can use.

It is deliberately narrow in three ways. It names one ADR, so setting it does not
open the others. It does not check WHAT changed -- this hook sees a path, not
content -- so the actual constraint is enforced afterwards by
verify-contracts.py, which diffs against HEAD and reports unless the Status line
is the only thing that moved. And it is not a general edit hatch: a body change
with the variable set passes here and is reported there, which is the outcome
that matters, because the write has landed either way and the report is what
reaches a human.

THIS IS HALF OF A PAIR
----------------------
Everything below reasons about the SHAPE of a command, which means it is a guess
about how a write will be spelled -- and the guess was wrong in the most ordinary
way available: `python3 - <<'PY'` calling pathlib.write_text matches none of the
patterns here. Enumerating interpreters instead was considered and rejected as
the same game one level up (`uv run`, `env python`, `go run`, `./tool.py`, a make
target, a compiled binary), with false positives that would fire on merely
READING a protected path -- and committed ADRs have no override, so a false block
on one has no way through.

verify-contracts.py is the answer: a PostToolUse hook that asks whether a frozen
file differs from HEAD, which no spelling can evade. This file still earns its
place by PREVENTING the common cases rather than reporting them afterwards; the
two are prevention and detection, not alternatives.

BIAS
----
This guard fails closed, which is the opposite of lab-scope-guard.py. That guard
sanitises heredoc bodies so documentation mentioning `nmap` is not mistaken for
an invocation, because a guard that fires on prose gets routed around. Here the
cost of a false block is one environment variable, and the cost of a false allow
is a silently broken contract, so a protected path appearing anywhere near a
write construct is blocked without further analysis.

Run the tests: python3 .claude/hooks/test_protect_contracts.py
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(os.environ.get("CLAUDE_PROJECT_DIR", ".")).resolve()

ESCAPE_VAR = "CVAP_ALLOW_PROTO_EDIT"

# The supersession hatch. Names ONE ADR by number: CVAP_SUPERSEDE_ADR=035.
SUPERSEDE_VAR = "CVAP_SUPERSEDE_ADR"

PROTO_MSG = """BLOCKED: proto/ is the frozen wire contract (ADR-022).

Scan points in customer networks run months-old builds, so changes must be
additive-only within a major version: no field removal, no renumbering, no
changed semantics for an existing field.

If the change is genuinely additive, authorise it by setting
CVAP_ALLOW_PROTO_EDIT=1 in this hook's environment, and record the addition in
the ADR. An assignment inside the command does not count and will not work: the
override has to come from the operator, not from whatever composed the command.
If it is not additive, it needs a major version and a migration plan first.

buf breaking enforces the same rule mechanically in CI; this hook is the
earlier, cheaper failure."""

ADR_MSG = """BLOCKED: this ADR is Accepted and committed. Accepted decisions are
superseded, not edited.

Write a new ADR that supersedes it, then set the old one's status to
"Superseded by ADR-NNN". Use /new-adr to scaffold it.

To SUPERSEDE it -- which needs one edit, setting its status to
"Superseded by ADR-NNN" -- set CVAP_SUPERSEDE_ADR=<nnn> in this hook's
environment, naming this ADR. That permits the status change and nothing else:
verify-contracts.py diffs the result against HEAD and reports if anything but the
Status line moved. CVAP_ALLOW_PROTO_EDIT does not apply here; it is for proto/
only.

An ADR with no commit in HEAD is still a draft and is editable -- if you are
seeing this for a file you wrote in this session, it has already been
committed."""

# A write construct anywhere in the same command segment as a protected path is
# enough to block. Kept narrow enough that reads -- cat, grep, git diff, buf
# lint -- are not caught by it.
SED_IN_PLACE = re.compile(r"\bsed\b[^\n]*?(?:\s-\w*i\w*\b|\s--in-place\b)")
WRITE_COMMANDS = re.compile(r"(?:^|[\s;&|(])(?:mv|cp|rm|truncate|install|dd)\b")
REDIRECT = re.compile(r"(?<![0-9<>])>>?\s*(['\"]?)([^\s;|&<>'\"]+)\1")
TEE = re.compile(r"\btee\b((?:\s+-{1,2}\w+)*)((?:\s+[^\s;|&<>]+)+)")

# Candidate protected paths, matched loosely so that quoting, ./ prefixes and
# absolute paths all land in the same bucket.
PROTO_PATH = re.compile(r"[\w./~$-]*\bproto/[\w./$-]*\.proto\b")
ADR_PATH = re.compile(r"[\w./~$-]*\bdocs/adr/[\w.$-]*\.md\b")


def _segments(command: str) -> list[str]:
    """Split on shell separators and newlines.

    A heredoc redirect target sits on the line that opens the heredoc, so the
    target is always found before the split that the body would cause.
    """
    return [s for s in re.split(r"[;&|\n]+", command) if s.strip()]


def is_protected_proto(path: str) -> bool:
    """A .proto file with a proto/ directory component.

    The directory component is what keeps an unrelated .proto elsewhere in the
    tree -- an engine's internal job contract, say (ADR-027) -- editable. Only
    the published wire contract under proto/ is frozen.
    """
    parts = pathlib.PurePosixPath(path.strip("'\"")).parts
    return path.strip("'\"").endswith(".proto") and "proto" in parts[:-1]


def _is_committed(relative: str) -> bool:
    """Whether this path exists in HEAD.

    Fails CLOSED in every uncertain case, which is this guard's bias: a missing
    git binary, a directory that is not a repository, an unborn HEAD or a
    timeout all report "committed", so the ADR stays protected. Only a clean
    "git knows this repository and that path is not in HEAD" opens the file.

    Three calls, and each rules out a way of getting the wrong answer.

    `--show-toplevel` must equal ROOT. git resolves `-C <dir>` by walking UP to
    the enclosing repository, so a ROOT that is a subdirectory would have its
    paths resolved against the repository root instead -- `docs/adr/x.md` would
    be looked up as if ROOT were the top, find nothing, and report every ADR
    beneath it as an editable draft. Requiring ROOT to BE the toplevel is what
    makes the relative path below mean what it says.

    `rev-parse --verify HEAD` establishes that the question is answerable at
    all: `cat-file -e` cannot distinguish "not in HEAD" from "there is no HEAD",
    and a fresh repository with no commits must not read as "nothing is frozen".

    Only then does `cat-file -e` answer it.
    """
    try:
        top = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=5,
        )
        if top.returncode != 0:
            return True
        if pathlib.Path(top.stdout.strip()).resolve() != ROOT:
            return True

        head = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "--verify", "--quiet", "HEAD"],
            capture_output=True, timeout=5,
        )
        if head.returncode != 0:
            return True

        found = subprocess.run(
            ["git", "-C", str(ROOT), "cat-file", "-e", "HEAD:" + relative],
            capture_output=True, timeout=5,
        )
        return found.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return True


def adr_number(name: str) -> str | None:
    """The leading number of an ADR filename, e.g. 035-foo.md -> 035."""
    m = re.match(r"^(\d{3})-", name)
    return m.group(1) if m else None


def superseding(name: str) -> bool:
    """Whether the operator has authorised a supersession edit to THIS ADR.

    Compared as integers so 35 and 035 both name ADR-035, and an unset or
    unparseable value authorises nothing.
    """
    want = os.environ.get(SUPERSEDE_VAR, "").strip()
    have = adr_number(name)
    if not want or have is None:
        return False
    try:
        return int(want) == int(have)
    except ValueError:
        return False


def is_protected_adr(path: str) -> bool:
    """An Accepted ADR that has been committed, excluding the index.

    A path that does not exist yet is a new ADR being written, which is allowed.
    So is one whose status is Proposed -- an ADR is only immutable once accepted.
    So is one that is accepted but not yet committed: see UNCOMMITTED ADRs above.
    """
    p = pathlib.PurePosixPath(path.strip("'\""))
    if p.suffix != ".md" or "adr" not in p.parts[:-1] or "docs" not in p.parts[:-1]:
        return False
    if p.name == "000-index.md":
        return False
    candidate = ROOT / "docs" / "adr" / p.name
    try:
        text = candidate.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    if not re.search(r"^\*\*Status:\*\*\s*Accepted", text, re.MULTILINE | re.IGNORECASE):
        return False
    if superseding(p.name):
        # Authorised, and bounded by verify-contracts.py afterwards: it reports
        # unless the Status line is the only thing that changed.
        return False
    return _is_committed("docs/adr/" + p.name)


def classify(path: str) -> str | None:
    if is_protected_proto(path):
        return PROTO_MSG
    if is_protected_adr(path):
        return ADR_MSG
    return None


def written_paths(segment: str) -> list[str]:
    """Protected paths this segment could be writing to.

    Redirect and tee targets are read precisely. For the mutating commands the
    whole segment is swept instead: `mv proto/a.proto proto/b.proto` removes a
    frozen file whichever end of it you look at, and distinguishing source from
    destination buys nothing a block does not already give.
    """
    hits: list[str] = []

    for _, target in REDIRECT.findall(segment):
        hits.append(target)

    for _flags, args in TEE.findall(segment):
        hits.extend(args.split())

    if SED_IN_PLACE.search(segment) or WRITE_COMMANDS.search(segment):
        hits.extend(PROTO_PATH.findall(segment))
        hits.extend(ADR_PATH.findall(segment))

    return hits


def escaped() -> bool:
    """The override, honoured only from the hook's own environment.

    Deliberately not readable from the command string. See ESCAPE HATCH above:
    an override that anything composing a command can write into it is one that
    anything composing a command can use.
    """
    return os.environ.get(ESCAPE_VAR, "0") == "1"


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0

    tool_input = payload.get("tool_input") or {}

    file_path = tool_input.get("file_path") or ""
    command = tool_input.get("command") or ""

    if file_path:
        message = classify(file_path)
        if message is None:
            return 0
        if message is PROTO_MSG and escaped():
            return 0
        print(message, file=sys.stderr)
        return 2

    if not command:
        return 0

    for segment in _segments(command):
        for candidate in written_paths(segment):
            message = classify(candidate)
            if message is None:
                continue
            if message is PROTO_MSG and escaped():
                return 0
            print(message, file=sys.stderr)
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
