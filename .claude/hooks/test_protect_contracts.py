#!/usr/bin/env python3
"""Test suite for protect-contracts.py.

The guard was extended from file_path mode to command mode because a Bash
heredoc was a straight path through it. An extension like that is exactly the
kind that looks done and is not -- adding Bash to the settings.json matcher
without teaching the script to read a command would have made every Bash call
present an empty path and exit 0. So it gets a case table, not trust, the same
way lab-scope-guard.py does.

ALLOW means exit 0 (the tool call proceeds). BLOCK means exit 2 (the hook stops
it and returns the message to Claude).

Run: python3 .claude/hooks/test_protect_contracts.py
"""

from __future__ import annotations

import atexit
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
HOOK = ROOT / ".claude" / "hooks" / "protect-contracts.py"

ALLOW, BLOCK = "ALLOW", "BLOCK"


def _draft_repo() -> pathlib.Path:
    """A throwaway repository holding one committed and one uncommitted ADR.

    Built rather than borrowed. The real tree cannot demonstrate both halves at
    once: every ADR in it is committed, and an uncommitted fixture placed there
    would be committed by the very session that needs to test the case -- and
    would then start failing. A temporary repository pins both states and mutates
    nothing anyone is working in.
    """
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="cvap-adr-guard-"))
    atexit.register(shutil.rmtree, tmp, ignore_errors=True)

    adr = tmp / "docs" / "adr"
    adr.mkdir(parents=True)
    body = "# ADR-900: fixture\n\n**Status:** Accepted\n**Date:** 2026-09-02\n"
    (adr / "900-committed.md").write_text(body)

    git = ["git", "-c", "user.email=t@example.invalid", "-c", "user.name=t", "-C", str(tmp)]
    for args in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "fixture"]):
        subprocess.run(git + args, check=True, capture_output=True)

    # Written AFTER the commit, so it has no history at all.
    (adr / "901-uncommitted.md").write_text(body.replace("900", "901"))
    return tmp


def _plain_dir(with_git: bool) -> pathlib.Path:
    """A directory holding the same ADR, with no repository or with an empty one."""
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="cvap-adr-guard-"))
    atexit.register(shutil.rmtree, tmp, ignore_errors=True)
    adr = tmp / "docs" / "adr"
    adr.mkdir(parents=True)
    (adr / "901-uncommitted.md").write_text(
        "# ADR-901: fixture\n\n**Status:** Accepted\n**Date:** 2026-09-02\n")
    if with_git:
        subprocess.run(["git", "-C", str(tmp), "init", "-q"], check=True, capture_output=True)
    return tmp


def _nested_repo() -> pathlib.Path:
    """A repository whose ADRs live under a subdirectory, committed.

    Pointing CLAUDE_PROJECT_DIR at that subdirectory is what exercises the
    toplevel check: the file is readable from there, so the guard gets past its
    existence test and has to decide on git alone.
    """
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="cvap-adr-guard-"))
    atexit.register(shutil.rmtree, tmp, ignore_errors=True)
    adr = tmp / "sub" / "docs" / "adr"
    adr.mkdir(parents=True)
    (adr / "900-committed.md").write_text(
        "# ADR-900: fixture\n\n**Status:** Accepted\n**Date:** 2026-09-02\n")
    git = ["git", "-c", "user.email=t@example.invalid", "-c", "user.name=t", "-C", str(tmp)]
    for args in (["init", "-q"], ["add", "-A"], ["commit", "-q", "-m", "fixture"]):
        subprocess.run(git + args, check=True, capture_output=True)
    return tmp / "sub"


DRAFT_REPO = _draft_repo()
NO_REPO = _plain_dir(with_git=False)
EMPTY_REPO = _plain_dir(with_git=True)
NESTED_ROOT = _nested_repo()

FROZEN_PROTO = "proto/cybersentinel/scanpoint/v1/ingest.proto"

PROTO_HEREDOC = """cat > proto/cybersentinel/scanpoint/v1/ingest.proto <<'EOF'
syntax = "proto3";
package cybersentinel.scanpoint.v1;
EOF"""

INLINE_ESCAPE_HEREDOC = """CVAP_ALLOW_PROTO_EDIT=1 cat > proto/cybersentinel/scanpoint/v1/ingest.proto <<'EOF'
syntax = "proto3";
EOF"""

EXPORTED_ESCAPE_HEREDOC = "export CVAP_ALLOW_PROTO_EDIT=1\n" + PROTO_HEREDOC

# A read whose output is redirected somewhere harmless. The protected path is on
# the left of the redirect, not the right.
READ_THEN_REDIRECT = "cat proto/cybersentinel/scanpoint/v1/ingest.proto > /tmp/copy.txt"

# (name, tool_input dict, env overrides, expected)
CASES: list[tuple[str, dict, dict, str]] = [
    # --- command mode: the hole this rewrite closes ---
    ("heredoc writes a frozen proto", {"command": PROTO_HEREDOC}, {}, BLOCK),
    ("append redirect to a frozen proto",
     {"command": "echo 'string x = 9;' >> proto/cybersentinel/scanpoint/v1/ingest.proto"}, {}, BLOCK),
    ("tee into a frozen proto",
     {"command": "echo hi | tee proto/cybersentinel/scanpoint/v1/common.proto"}, {}, BLOCK),
    ("tee -a into a frozen proto",
     {"command": "echo hi | tee -a proto/cybersentinel/scanpoint/v1/common.proto"}, {}, BLOCK),
    ("sed -i on a frozen proto",
     {"command": "sed -i 's/int64/int32/' proto/cybersentinel/scanpoint/v1/dispatch.proto"}, {}, BLOCK),
    ("mv renames a frozen proto",
     {"command": "mv proto/cybersentinel/scanpoint/v1/a.proto proto/cybersentinel/scanpoint/v1/b.proto"}, {}, BLOCK),
    ("cp over a frozen proto",
     {"command": "cp /tmp/new.proto proto/cybersentinel/scanpoint/v1/ingest.proto"}, {}, BLOCK),
    ("rm deletes a frozen proto",
     {"command": "rm proto/cybersentinel/scanpoint/v1/ingest.proto"}, {}, BLOCK),
    ("truncate empties a frozen proto",
     {"command": "truncate -s 0 proto/cybersentinel/scanpoint/v1/ingest.proto"}, {}, BLOCK),
    ("absolute path is still the frozen contract",
     {"command": "echo x > /home/ubuntu/CVAP/proto/cybersentinel/scanpoint/v1/ingest.proto"}, {}, BLOCK),
    ("write hidden behind a chained command",
     {"command": "go build ./... && echo x > proto/cybersentinel/scanpoint/v1/ingest.proto"}, {}, BLOCK),

    # --- command mode: Accepted ADRs ---
    ("sed -i on an Accepted ADR",
     {"command": "sed -i 's/Accepted/Proposed/' docs/adr/005-outbound-only-grpc-mtls.md"}, {}, BLOCK),
    ("redirect over an Accepted ADR",
     {"command": "cat > docs/adr/022-additive-only-protocol-versioning.md <<'EOF'\nrewritten\nEOF"}, {}, BLOCK),
    ("the ADR index is appendable",
     {"command": "cat >> docs/adr/000-index.md <<'EOF'\n| 028 | Something | Accepted |\nEOF"}, {}, ALLOW),
    ("a new ADR that does not exist yet",
     {"command": "cat > docs/adr/028-new-decision.md <<'EOF'\n**Status:** Proposed\nEOF"}, {}, ALLOW),

    # --- command mode: reads and unrelated work must not be caught ---
    ("cat a frozen proto",
     {"command": "cat proto/cybersentinel/scanpoint/v1/ingest.proto"}, {}, ALLOW),
    ("grep a frozen proto",
     {"command": "grep -n lease_epoch proto/cybersentinel/scanpoint/v1/dispatch.proto"}, {}, ALLOW),
    ("git diff a frozen proto",
     {"command": "git diff proto/cybersentinel/scanpoint/v1/ingest.proto"}, {}, ALLOW),
    ("buf lint reads the whole module", {"command": "buf lint proto"}, {}, ALLOW),
    ("a read whose output goes somewhere harmless",
     {"command": READ_THEN_REDIRECT}, {}, ALLOW),
    ("read an Accepted ADR", {"command": "cat docs/adr/012-lease-epoch-fencing.md"}, {}, ALLOW),
    ("a .proto outside proto/ is not the wire contract",
     {"command": "cat > internal/engines/jobcontract.proto <<'EOF'\nsyntax = \"proto3\";\nEOF"}, {}, ALLOW),
    ("an unrelated markdown file under docs/",
     {"command": "echo x > docs/architecture-v2.md"}, {}, ALLOW),
    ("ordinary build command", {"command": "go build ./..."}, {}, ALLOW),
    ("no command and no path at all", {}, {}, ALLOW),

    # --- the escape hatch: the environment, and only the environment ---
    #
    # An override reachable from inside the command string is reachable by
    # anything that composes commands, including a future session that hits
    # this guard and routes around it rather than asking. Requiring the
    # environment is what makes the bypass need a human to act, which is the
    # entire point of a freeze. These cases are that distinction, asserted in
    # both directions so neither half can rot.
    ("inline assignment does NOT authorise the write",
     {"command": INLINE_ESCAPE_HEREDOC}, {}, BLOCK),
    ("an exported assignment in the command does NOT authorise it either",
     {"command": EXPORTED_ESCAPE_HEREDOC}, {}, BLOCK),
    ("environment variable authorises the write",
     {"command": PROTO_HEREDOC}, {"CVAP_ALLOW_PROTO_EDIT": "1"}, ALLOW),
    ("environment variable authorises an in-place edit too",
     {"command": "sed -i 's/int64/int32/' " + FROZEN_PROTO},
     {"CVAP_ALLOW_PROTO_EDIT": "1"}, ALLOW),
    ("escape set to something other than 1 does not authorise",
     {"command": PROTO_HEREDOC}, {"CVAP_ALLOW_PROTO_EDIT": "0"}, BLOCK),
    ("the escape does not reach Accepted ADRs",
     {"command": "sed -i 's/x/y/' docs/adr/005-outbound-only-grpc-mtls.md"},
     {"CVAP_ALLOW_PROTO_EDIT": "1"}, BLOCK),

    # --- file_path mode: the original behaviour must still hold ---
    ("Write to a frozen proto",
     {"file_path": str(ROOT / "proto/cybersentinel/scanpoint/v1/ingest.proto")}, {}, BLOCK),
    ("Write to a relative frozen proto path",
     {"file_path": "proto/cybersentinel/scanpoint/v1/ingest.proto"}, {}, BLOCK),
    ("Edit an Accepted ADR",
     {"file_path": str(ROOT / "docs/adr/026-result-submission-contract.md")}, {}, BLOCK),
    ("Edit the ADR index", {"file_path": str(ROOT / "docs/adr/000-index.md")}, {}, ALLOW),
    ("Write an ordinary Go file", {"file_path": str(ROOT / "internal/logging/logging.go")}, {}, ALLOW),
    ("escape authorises a Write to a frozen proto",
     {"file_path": "proto/cybersentinel/scanpoint/v1/ingest.proto"},
     {"CVAP_ALLOW_PROTO_EDIT": "1"}, ALLOW),

    # --- an uncommitted ADR is still a draft ---
    #
    # An ADR is frozen by being COMMITTED, not by carrying the word Accepted.
    # The guard used to block the author's own correction to a document that had
    # never left one working tree, with no override, which is not what the
    # freeze is for. Both directions are asserted so neither half can rot: the
    # exemption must open a draft, and it must not open anything else.
    ("an Accepted ADR with no commit in HEAD is a draft",
     {"file_path": "docs/adr/901-uncommitted.md"},
     {"CLAUDE_PROJECT_DIR": str(DRAFT_REPO)}, ALLOW),
    ("the same file, once committed, is frozen",
     {"file_path": "docs/adr/900-committed.md"},
     {"CLAUDE_PROJECT_DIR": str(DRAFT_REPO)}, BLOCK),
    ("a draft is editable from a command too",
     {"command": "sed -i 's/x/y/' docs/adr/901-uncommitted.md"},
     {"CLAUDE_PROJECT_DIR": str(DRAFT_REPO)}, ALLOW),
    ("a committed one is not, from a command either",
     {"command": "sed -i 's/x/y/' docs/adr/900-committed.md"},
     {"CLAUDE_PROJECT_DIR": str(DRAFT_REPO)}, BLOCK),

    # The exemption must not become a way to reach a real, committed decision.
    # ADR-029 is the one this session had to amend, so it is the one named here.
    ("ADR-029 in the real tree still blocks",
     {"file_path": str(ROOT / "docs/adr/029-schema-tables-the-erd-lacks.md")}, {}, BLOCK),
    ("ADR-029 still blocks with the proto escape set",
     {"file_path": str(ROOT / "docs/adr/029-schema-tables-the-erd-lacks.md")},
     {"CVAP_ALLOW_PROTO_EDIT": "1"}, BLOCK),

    # Fail closed, three ways. Each of these is a route to the wrong answer if
    # the check is written casually.
    ("a project dir that is not a repository at all cannot answer, so it blocks",
     {"file_path": "docs/adr/901-uncommitted.md"},
     {"CLAUDE_PROJECT_DIR": str(NO_REPO)}, BLOCK),
    ("a repository with no commits does not read as nothing-is-frozen",
     {"file_path": "docs/adr/901-uncommitted.md"},
     {"CLAUDE_PROJECT_DIR": str(EMPTY_REPO)}, BLOCK),
    # git resolves -C by walking UP to the enclosing repository, so a project
    # dir below the toplevel would have docs/adr/x.md looked up against the
    # WRONG base, find nothing, and call every ADR beneath it a draft.
    ("a project dir below the repository toplevel blocks rather than guessing",
     {"file_path": "docs/adr/900-committed.md"},
     {"CLAUDE_PROJECT_DIR": str(NESTED_ROOT)}, BLOCK),
]


def run(tool_input: dict, env_overrides: dict) -> int:
    payload = json.dumps({"tool_input": tool_input})
    env = {"CLAUDE_PROJECT_DIR": str(ROOT), "PATH": "/usr/bin:/bin"}
    env.update(env_overrides)
    proc = subprocess.run(
        [sys.executable, str(HOOK)],
        input=payload,
        capture_output=True,
        text=True,
        env=env,
    )
    return proc.returncode


def main() -> int:
    width = max(len(name) for name, _, _, _ in CASES)
    failures = 0

    print(f"{'#':>3}  {'case'.ljust(width)}  {'want':<5}  {'got':<5}  result")
    print("-" * (width + 30))

    for i, (name, tool_input, env_overrides, want) in enumerate(CASES, 1):
        code = run(tool_input, env_overrides)
        got = ALLOW if code == 0 else BLOCK if code == 2 else f"exit {code}"
        ok = got == want
        failures += not ok
        print(f"{i:>3}  {name.ljust(width)}  {want:<5}  {got:<5}  {'PASS' if ok else 'FAIL'}")

    print("-" * (width + 30))
    print(f"{len(CASES) - failures}/{len(CASES)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
