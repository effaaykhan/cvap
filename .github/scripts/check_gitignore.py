#!/usr/bin/env python3
"""Assert .gitignore still covers what it is supposed to cover.

This exists because .gitignore was once overwritten wholesale by someone who had
not read it first, silently dropping four categories of entry: the Python
artefacts, the local Claude config overrides, the lab capture paths, and the
build outputs. Nothing failed. The loss would have surfaced as a committed
virtualenv or a committed settings.local.json weeks later.

A .gitignore is a security control here as much as a hygiene one: it is what
stops key material and a developer's local credentials reaching the remote. It
should be tested like one.

Asserts both directions — that sensitive paths ARE ignored, and that paths which
must stay committable are NOT. The second half matters just as much: an
over-broad rule that swallows .env.example or .claude/agents/ breaks the repo in
a way that is easy to "fix" by deleting the rule that was protecting something
else.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

# (path, must_be_ignored, why)
CASES: list[tuple[str, bool, str]] = [
    (".env", True, "local credentials must never reach the remote"),
    (".env.local", True, "any .env variant"),
    (".env.example", False, "the committed template developers copy from"),
    # Deliberately not a .pyc: that would also be caught by *.py[cod], so the
    # case would pass even if the __pycache__/ rule were deleted.
    ("knowledge/__pycache__/index.txt", True, "__pycache__ dirs from knowledge/ pipelines"),
    ("knowledge/module.pyc", True, "compiled python artefacts"),
    (".venv/pyvenv.cfg", True, "python virtualenv"),
    (".claude/settings.local.json", True, "personal overrides, not shared config"),
    (".claude/agent-memory-local/note.md", True, "local agent memory"),
    (".claude/agents/security-reviewer.md", False, "shared config, must be committed"),
    (".claude/skills/cvap-invariants/SKILL.md", False, "shared config, must be committed"),
    (".claude/settings.json", False, "shared hooks and permissions"),
    ("lab/captures/run.pcap", True, "packet captures may contain scan traffic"),
    ("lab/output/report.json", True, "lab run artefacts"),
    ("lab/scope.txt", False, "the allowlist the guard reads — must be committed"),
    ("lab/compose.yml", False, "the lab definition"),
    ("server.pem", True, "key material"),
    ("client.key", True, "key material"),
    ("secrets/token", True, "anything under secrets/"),
    ("bin/cvap-core", True, "build output"),
    ("coverage.out", True, "test artefact"),
    ("go.mod", False, "source of truth for the module"),
    ("Makefile", False, "committed build entrypoint"),
]


def is_ignored(path: str) -> bool:
    """git check-ignore exits 0 when the path is ignored, 1 when it is not."""
    proc = subprocess.run(
        ["git", "check-ignore", "-q", "--no-index", path],
        cwd=ROOT,
        capture_output=True,
    )
    if proc.returncode not in (0, 1):
        raise SystemExit(
            f"git check-ignore failed for {path!r}: {proc.stderr.decode(errors='replace')}"
        )
    return proc.returncode == 0


def main() -> int:
    failures: list[str] = []
    width = max(len(p) for p, _, _ in CASES)

    print(f"{'path'.ljust(width)}  {'want':<9}  {'got':<9}  result")
    print("-" * (width + 32))

    for path, want_ignored, why in CASES:
        got_ignored = is_ignored(path)
        ok = got_ignored == want_ignored
        if not ok:
            failures.append(
                f"{path}: expected {'ignored' if want_ignored else 'NOT ignored'} "
                f"({why})"
            )
        print(
            f"{path.ljust(width)}  "
            f"{'ignored' if want_ignored else 'tracked':<9}  "
            f"{'ignored' if got_ignored else 'tracked':<9}  "
            f"{'PASS' if ok else 'FAIL'}"
        )

    print("-" * (width + 32))
    if failures:
        print(f"\n.gitignore regression ({len(failures)} failure(s)):", file=sys.stderr)
        for line in failures:
            print(f"  {line}", file=sys.stderr)
        print(
            "\nIf a rule was removed deliberately, update this test in the same commit "
            "so the change is visible in review.",
            file=sys.stderr,
        )
        return 1

    print(f"{len(CASES)}/{len(CASES)} passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
