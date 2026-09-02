#!/usr/bin/env python3
"""Test suite for lab-scope-guard.py.

SETUP.md records that the guard was "tested against seventeen cases" but the
suite itself was never committed. Cases 1-17 below reconstruct it from the
documented behaviour, including the five invocations SETUP.md names verbatim.
Cases 18-20 cover heredoc and redirect sanitising.

ALLOW means exit 0 (the command runs). BLOCK means exit 2 (the hook stops it).

Run: python3 .claude/hooks/test_lab_scope_guard.py
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
HOOK = ROOT / ".claude" / "hooks" / "lab-scope-guard.py"

ALLOW, BLOCK = "ALLOW", "BLOCK"

DOC_HEREDOC = """cat > docs/guard.md <<'EOF'
The guard blocks an out-of-scope scan. For example, `cvap-cli scan 8.8.8.8`
is refused, and so is `nmap -iL targets.txt`.
EOF"""

DOC_HEREDOC_THEN_SCAN = """cat > docs/guard.md <<'EOF'
Documentation mentioning cvap-cli scan 8.8.8.8 as an example.
EOF
cvap-cli scan 8.8.8.8"""

CASES: list[tuple[str, str, str]] = [
    # --- reconstructed originals: allowed ---
    ("in-scope host-only VM", "nmap 192.168.56.101", ALLOW),
    ("soft tool, hostname only", "curl https://proxy.golang.org", ALLOW),
    ("lab segment A target", "nmap 10.10.0.11", ALLOW),
    ("loopback", "nmap 127.0.0.1", ALLOW),
    ("documentation range", "masscan 192.0.2.0/24", ALLOW),
    ("soft tool, in-scope literal", "curl http://10.10.0.11/", ALLOW),
    ("not a tool at all", "go build ./...", ALLOW),
    ("scan tool, in-scope, other flags", "ssh 10.10.0.11", ALLOW),
    ("tool name inside a commit message", 'git commit -m "add nmap parser"', ALLOW),
    # --- reconstructed originals: blocked ---
    ("public DNS resolver", "cvap-cli scan 8.8.8.8", BLOCK),
    ("the entire internet", "masscan 0.0.0.0/0", BLOCK),
    ("targets from a file", "nmap -iL targets.txt", BLOCK),
    ("soft tool, out-of-scope literal", "curl http://45.33.32.156/", BLOCK),
    ("one in scope, one not", "nmap 8.8.8.8 192.168.56.10", BLOCK),
    ("out-of-scope literal", "zmap 1.1.1.1", BLOCK),
    ("target via variable", "nmap $TARGET", BLOCK),
    ("out-of-scope IPv6", "nmap 2001:4860:4860::8888", BLOCK),
    # --- new: heredoc and redirect sanitising ---
    ("heredoc body is documentation, not a command", DOC_HEREDOC, ALLOW),
    ("real invocation after the heredoc delimiter", DOC_HEREDOC_THEN_SCAN, BLOCK),
    ("write to a path containing a tool name", "cat > cvap <<'EOF'\nnotes\nEOF", ALLOW),
    # --- new: sanitising must not open a hole ---
    ("variable target survives sanitising", "TARGET=8.8.8.8; cvap-cli scan $TARGET", BLOCK),
    ("redirect does not launder the target", "nmap 8.8.8.8 > /tmp/out.txt", BLOCK),
    # --- new: the database role is not a scan tool ---
    #
    # The false positive that prompted narrowing SCAN_TOOLS. `cvap` is the
    # database role as well as the module name; it is not a binary. Blocking
    # this taught people to phrase psql differently, which is how a guard stops
    # being one.
    ("psql as the cvap role", "psql -U cvap -d cvap -c 'SELECT 1'", ALLOW),
    ("psql long-form, same thing", "psql --username=cvap --dbname=cvap", ALLOW),
    ("go module path mentions cvap", "go test github.com/effaaykhan/cvap/...", ALLOW),
    # --- new: a path separator is not a word boundary ---
    #
    # These are the hole the narrowing exposed. A locally built binary is run as
    # ./cvap-cli, and the old prefix class ([\s;&|(]) did not accept the slash,
    # so the most natural invocation was never matched at all.
    ("locally built binary, out of scope", "./cvap-cli scan 8.8.8.8", BLOCK),
    ("absolute path to a scan tool", "/usr/bin/nmap 8.8.8.8", BLOCK),
    ("in-scope via a path", "./cvap-cli scan 10.10.0.11", ALLOW),
    ("path that merely contains a tool name", "cat docs/cvap-cli.md", ALLOW),
    ("directory named after a tool", "ls internal/nmap/parser.go", ALLOW),
    ("cvap-core is a binary and does dispatch", "cvap-core --target 8.8.8.8", BLOCK),
    # --- new: quoting and assignment are not a disguise ---
    #
    # A safety audit walked past the guard with each of these. 198.18.0.0/15 is
    # RFC 2544 benchmarking space: reserved, not routed, and not in lab scope,
    # so these are out-of-scope literals that send nothing if the guard leaks.
    ("double-quoted invocation", 'bash -c "nmap 198.18.0.1"', BLOCK),
    ("single-quoted invocation", "sh -c 'nmap 198.18.0.1'", BLOCK),
    ("command substitution", "echo `nmap 198.18.0.1`", BLOCK),
    ("tool name assigned to a variable", "CMD=nmap; $CMD 198.18.0.1", BLOCK),
    ("quoting does not launder an in-scope target", 'bash -c "nmap 10.10.0.11"', ALLOW),
]


def run(command: str) -> int:
    payload = json.dumps({"tool_input": {"command": command}})
    proc = subprocess.run(
        [sys.executable, str(HOOK)],
        input=payload,
        capture_output=True,
        text=True,
        env={"CLAUDE_PROJECT_DIR": str(ROOT), "PATH": "/usr/bin:/bin"},
    )
    return proc.returncode


def main() -> int:
    width = max(len(name) for name, _, _ in CASES)
    failures = 0

    print(f"{'#':>3}  {'case'.ljust(width)}  {'want':<5}  {'got':<5}  result")
    print("-" * (width + 30))

    for i, (name, command, want) in enumerate(CASES, 1):
        code = run(command)
        got = ALLOW if code == 0 else BLOCK if code == 2 else f"exit {code}"
        ok = got == want
        failures += not ok
        print(f"{i:>3}  {name.ljust(width)}  {want:<5}  {got:<5}  {'PASS' if ok else 'FAIL'}")

    print("-" * (width + 30))
    print(f"{len(CASES) - failures}/{len(CASES)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
