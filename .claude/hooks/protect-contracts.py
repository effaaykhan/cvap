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

ESCAPE HATCH
------------
A genuinely additive proto change, or the commit that establishes the baseline,
sets CVAP_ALLOW_PROTO_EDIT=1. In command mode the hook runs in Claude Code's
environment and not the command's, so an inline `CVAP_ALLOW_PROTO_EDIT=1 cmd`
assignment would never reach it. The hook therefore accepts either: the variable
in its own environment, or an explicit assignment written into the command. The
second form is deliberate — it leaves the override visible in the transcript
next to the write it authorised, rather than in an environment nobody can see.

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
import sys

ROOT = pathlib.Path(os.environ.get("CLAUDE_PROJECT_DIR", ".")).resolve()

ESCAPE_VAR = "CVAP_ALLOW_PROTO_EDIT"

PROTO_MSG = """BLOCKED: proto/ is the frozen wire contract (ADR-022).

Scan points in customer networks run months-old builds, so changes must be
additive-only within a major version: no field removal, no renumbering, no
changed semantics for an existing field.

If the change is genuinely additive, authorise it for one call by setting
CVAP_ALLOW_PROTO_EDIT=1 -- in the environment, or as an explicit assignment at
the front of the Bash command -- and record the addition in the ADR.
If it is not additive, it needs a major version and a migration plan first.

buf breaking enforces the same rule mechanically in CI; this hook is the
earlier, cheaper failure."""

ADR_MSG = """BLOCKED: this ADR is Accepted. Accepted decisions are superseded, not edited.

Write a new ADR that supersedes it, then set the old one's status to
"Superseded by ADR-NNN". Use /new-adr to scaffold it."""

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


def is_protected_adr(path: str) -> bool:
    """An Accepted ADR, excluding the index.

    A path that does not exist yet is a new ADR being written, which is allowed.
    So is one whose status is Proposed -- an ADR is only immutable once accepted.
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
    return bool(re.search(r"^\*\*Status:\*\*\s*Accepted", text, re.MULTILINE | re.IGNORECASE))


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


def escaped(command: str) -> bool:
    if os.environ.get(ESCAPE_VAR, "0") == "1":
        return True
    return bool(re.search(rf"(?:^|[\s;&|(]){ESCAPE_VAR}=1\b", command))


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
        if message is PROTO_MSG and os.environ.get(ESCAPE_VAR, "0") == "1":
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
            if message is PROTO_MSG and escaped(command):
                return 0
            print(message, file=sys.stderr)
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
