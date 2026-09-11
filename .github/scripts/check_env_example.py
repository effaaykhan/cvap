#!/usr/bin/env python3
"""Assert env.example documents exactly the environment the code reads.

This exists because a .env copied from an out-of-date env.example fails at the
worst possible moment: not at startup with a clear message, but later, when some
code path finally reads MINIO_BUCKET and finds an empty string. A missing key
becomes a mystery bug in a subsystem nobody was touching.

That is not hypothetical — it is how this check came to be written. A .env was
created without MINIO_BUCKET or LOG_LEVEL and nothing anywhere noticed.

Both directions are checked, and the second matters as much as the first:

  * A variable the code reads but env.example does not document. Anyone who
    sets up from the template gets a broken deployment and no clue why.

  * A variable env.example documents but nothing reads. That is rot: a key that
    once mattered, still being copied into every developer's .env and every
    deployment's secret store, still being rotated by someone, for nothing. It
    also erodes trust in the template — once a reader learns some keys are dead,
    they stop believing any of them are required.

Sources scanned for what "the code reads":

  * docker-compose.yml           ${VAR} and ${VAR:-default} and ${VAR:?msg}
  * Makefile                     $(VAR) referenced after the .env include
  * **/*.go                      os.Getenv("VAR") / os.LookupEnv("VAR")
  * **/*.py                      os.environ["VAR"] / os.environ.get("VAR") /
                                 os.getenv("VAR")
  * .github/workflows/*.yml      env: blocks that name a project variable

Run standalone, or via `make env-check`, or in CI.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "env.example"

# Variables that are legitimately read but must NOT be documented in
# env.example, with the reason. Keep this list short and justified — it is the
# escape hatch, and an unexplained entry here is how a real gap gets hidden.
ALLOWED_UNDOCUMENTED: dict[str, str] = {
    # Set by the test harness and CI, never by a developer's .env. Documenting
    # it would imply the app reads it, which it does not.
    "CVAP_TEST_DATABASE_URL": "set by CI and the test harness, not by .env",
    # Set by CI (and a developer running the oracle deliberately) to make the
    # version-comparator differential against dpkg/librpm fatal when the tool is
    # absent — same shape as CVAP_REQUIRE_LAB. Read only by a _test.go, never by
    # the app, so documenting it in env.example would imply the app reads it.
    "CVAP_REQUIRE_VERCMP_ORACLE": "set by CI/the test harness to require the vercmp oracle, not by .env",
    # The operator-run measurement instrument's password-auth mode (S40). A
    # password for a one-off run belongs in that shell, never in a .env template
    # that gets copied around; documenting it would invite exactly that.
    "CVAP_CREDSCAN_PASSWORD": "cvap-credscan instrument, passed in the shell for a one-off run, never .env",
    # The re-exec trigger for the scan-point test that spawns the test binary
    # as an engine child to prove the agent socket reaches fd 3. Set by the
    # test's own wrapper script, read only by a _test.go.
    "CVAP_TEST_HELPER_ENGINE": "set by credentialed_test.go's helper-process wrapper, never by .env",
    # Standard libpq and Docker variables the tooling passes through.
    "PGPASSWORD": "libpq, passed explicitly by tooling",
    "PGOPTIONS": "libpq, passed explicitly by tooling",
    "CURDIR": "make builtin, not an environment variable",
    "HOME": "provided by the OS",
    "PATH": "provided by the OS",
    "SHELL": "provided by the OS",
    "USER": "provided by the OS",
    "GOPATH": "Go toolchain variable, provided by the environment or go env",
    "GOBIN": "Go toolchain variable, provided by the environment or go env",
}

# Documented in env.example but not yet read by any scanned source.
#
# Every entry here is a promise that something will read it, with the thing
# named. That is the difference between a documented gap and rot: rot is a key
# nobody can say the purpose of. Delete the entry when the reader lands — and if
# an entry is still here in three months, the honest move is to delete the key
# from env.example instead.
ALLOWED_UNREAD: dict[str, str] = {
    "APP_DATABASE_URL": (
        "will be read by cmd/cvap-core to open the store pool as the application "
        "role. Added with internal/store; the binary is still a stub."
    ),
    "MINIO_BUCKET": (
        "will be read by the object-store client for evidence and reports "
        "(ADR-015). No such package exists yet."
    ),
    "LOG_LEVEL": (
        "will be read by internal/logging when slog level becomes configurable. "
        "The package currently hardcodes its handler."
    ),
}

VAR = r"[A-Z][A-Z0-9_]*"


def example_keys() -> tuple[list[str], list[str]]:
    """Return (keys in order, duplicate keys)."""
    if not EXAMPLE.exists():
        print(f"FAIL: {EXAMPLE} does not exist", file=sys.stderr)
        sys.exit(1)

    keys: list[str] = []
    dupes: list[str] = []
    for raw in EXAMPLE.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(rf"^({VAR})=", line)
        if not m:
            print(f"FAIL: {EXAMPLE.name}: cannot parse line: {raw!r}", file=sys.stderr)
            sys.exit(1)
        key = m.group(1)
        if key in keys:
            dupes.append(key)
        keys.append(key)
    return keys, dupes


def referenced() -> dict[str, set[str]]:
    """Map variable name -> set of files that reference it."""
    found: dict[str, set[str]] = {}

    def note(name: str, where: pathlib.Path) -> None:
        found.setdefault(name, set()).add(str(where.relative_to(ROOT)))

    compose = ROOT / "docker-compose.yml"
    if compose.exists():
        text = compose.read_text()
        # ${VAR}, ${VAR:-default}, ${VAR:?message}
        for m in re.finditer(rf"\$\{{({VAR})[}}:]", text):
            note(m.group(1), compose)

    makefile = ROOT / "Makefile"
    if makefile.exists():
        text = makefile.read_text()
        # A $(VAR) reference is only an ENVIRONMENT variable if the Makefile
        # does not assign it itself. MIGRATE_IMAGE, BUF_VERSION and friends are
        # make variables defined a few lines above their use — pinned tool
        # versions, not configuration a developer supplies — and demanding they
        # appear in env.example would be nonsense that trains people to add
        # entries to the allowlist without thinking.
        assigned = set(re.findall(rf"^({VAR})\s*[:?+]?=", text, re.M))
        # Variables make defines itself.
        builtin = {"MAKEFILE_LIST", "MAKEFLAGS", "MAKECMDGOALS", "CURDIR", "MAKE", "SHELL"}
        # Passed on the command line (make migrate-new NAME=x), not from .env.
        # LIMIT/PACKAGE are optional overrides for `make knowledge-usn` (the USN
        # ingestion); RELEASE-shaped inputs there carry ?= defaults so are already
        # in `assigned`.
        cli_args = {"NAME", "PROTO_BASELINE", "LIMIT", "PACKAGE"}
        for m in re.finditer(rf"\$\(({VAR})\)", text):
            name = m.group(1)
            if name in assigned or name in builtin or name in cli_args:
                continue
            note(name, makefile)

    for path in ROOT.rglob("*.go"):
        rel = path.relative_to(ROOT)
        if rel.parts[0] in {"gen", "web", ".git"}:
            continue
        text = path.read_text()
        for m in re.finditer(rf'os\.(?:Getenv|LookupEnv)\(\s*"({VAR})"', text):
            note(m.group(1), path)

    for path in ROOT.rglob("*.py"):
        rel = path.relative_to(ROOT)
        if rel.parts[0] in {".git"} or "__pycache__" in rel.parts:
            continue
        text = path.read_text()
        for m in re.finditer(rf'os\.environ(?:\.get)?[\[(]\s*["\']({VAR})["\']', text):
            note(m.group(1), path)
        for m in re.finditer(rf'os\.getenv\(\s*["\']({VAR})["\']', text):
            note(m.group(1), path)

    workflows = ROOT / ".github" / "workflows"
    if workflows.is_dir():
        for path in sorted(workflows.glob("*.yml")):
            text = path.read_text()
            for m in re.finditer(rf"^\s+({VAR}):\s", text, re.M):
                found.setdefault(m.group(1), set())
                found[m.group(1)].add(str(path.relative_to(ROOT)))

    return found


def main() -> int:
    keys, dupes = example_keys()
    documented = set(keys)
    refs = referenced()

    problems: list[str] = []

    for key in dupes:
        problems.append(
            f"{EXAMPLE.name} defines {key} more than once. "
            f"The last wins silently, so the two values disagree and nobody sees it."
        )

    # Direction 1: read but undocumented.
    for name, where in sorted(refs.items()):
        if name in documented or name in ALLOWED_UNDOCUMENTED:
            continue
        # Only complain about names that look like project configuration. A
        # workflow env: block names plenty of things that are not.
        if not any(
            w.startswith(("docker-compose", "Makefile", "cmd/", "internal/", "knowledge/"))
            for w in where
        ):
            continue
        problems.append(
            f"{name} is read by {', '.join(sorted(where))} but is not in "
            f"{EXAMPLE.name}. Anyone setting up from the template gets an empty "
            f"value and a failure somewhere unrelated."
        )

    # Direction 2: documented but unread.
    for name in keys:
        if name in refs or name in ALLOWED_UNREAD:
            continue
        problems.append(
            f"{name} is documented in {EXAMPLE.name} but nothing reads it. "
            f"Either wire it up or delete it — a dead key still gets copied into "
            f"every deployment and rotated by someone."
        )

    if problems:
        print("check_env_example: FAIL\n", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print(
            f"\n{len(problems)} problem(s). If a variable is legitimately absent "
            f"from one side, add it to ALLOWED_UNDOCUMENTED or ALLOWED_UNREAD in "
            f"{pathlib.Path(__file__).name} WITH a reason.",
            file=sys.stderr,
        )
        return 1

    print(f"check_env_example: OK — {len(keys)} keys in {EXAMPLE.name}, all read, none missing")
    return 0


if __name__ == "__main__":
    sys.exit(main())
