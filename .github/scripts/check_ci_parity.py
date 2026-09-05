#!/usr/bin/env python3
"""Every target in the Makefile `ci` line must actually run in GitHub CI.

Two registries that must agree, reconciled here rather than by someone
noticing -- the same shape as the ADR index gate:

  - the `ci:` prerequisite list in the Makefile (what `make ci` runs locally);
  - the steps in .github/workflows/ci.yml (what GitHub Actions actually runs).

These diverge silently. The workflow has its own hand-written job list and does
NOT call `make ci`, so a check added to the Makefile aggregate can be green in
`make ci` and never execute in CI. That is exactly how corpus-check and
adr-index shipped enforced-locally-only, and how the metrics half of the corpus
gate claimed "fatal in CI" while no job ran it.

A target is "in the workflow" when its SIGNATURE -- the concrete command or
action that IS its work -- appears in the executable surface of the workflow
(the run:, uses: and env: of the steps, never the comments). The mapping is
explicit because the relationship is not mechanical: `lint` is an action,
`db-gates` is decomposed into six schema-job steps, `proto` into three. A naive
"grep for `make <target>`" would report a dozen false gaps.

The mapping is itself a registry, so it is kept honest in both directions:
  - a `ci` target with no SIGNATURE and no ALLOWLIST entry fails the gate,
    which forces whoever adds a target to say how CI runs it (or why it does
    not);
  - a SIGNATURE or ALLOWLIST entry that is no longer a `ci` prerequisite fails
    the gate, so the mapping cannot rot into describing a target that is gone.

Where a target genuinely should not run in CI, it goes in ALLOWLIST with a
reason -- an explicit line, not silence.
"""

import pathlib
import re
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
MAKEFILE = ROOT / "Makefile"
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"

# For each `ci` target: the substrings that PROVE its work runs in the workflow.
# All strings in a target's list must be present. Keep them specific -- a loose
# signature that matches a comment or an unrelated step defeats the gate.
SIGNATURES = {
    "fmt-check":           ["gofmt -l"],
    "tidy-check":          ["go mod tidy", "git diff --exit-code -- go.mod go.sum"],
    "build":               ["go build ./..."],
    "vet":                 ["go vet ./..."],
    "test":                ["go test ./... -race"],
    # golangci-lint runs as an action, not as `golangci-lint run`.
    "lint":                ["golangci/golangci-lint-action"],
    "gosec":               ["gosec -exclude-dir=gen ./..."],
    "govulncheck":         ["govulncheck ./..."],
    # proto is three sub-targets; the additive-only step runs proto-breaking
    # through its own script rather than by name, so match that target.
    "proto":               ["make proto-lint", "make proto-verify", "proto-breaking"],
    "frontmatter":         ["check_frontmatter.py"],
    "gitignore-test":      ["check_gitignore.py"],
    "scope-guard-test":    ["test_lab_scope_guard.py"],
    "contract-guard-test": ["test_protect_contracts.py", "test_verify_contracts.py"],
    "secret-logging":      ["check_secret_logging.py"],
    "secret-logging-test": ["test_check_secret_logging.py"],
    "env-check":           ["check_env_example.py"],
    "licences":            ["check_licences.py"],
    # db-gates is decomposed into the schema job's steps. Require the load-
    # bearing ones by name, so deleting any of them from CI fails here.
    "db-gates":            ["make migrate-verify", "make app-role", "make rls-test",
                            "make store-test", "make mutate"],
    "adr-index":           ["check_adr_index.py"],
    # corpus-check has two halves and BOTH must run: the always-on labels (the
    # config job) and the enforced metrics (the corpus job, whose whole point is
    # CVAP_REQUIRE_LAB=1). Requiring the env var here means deleting the corpus
    # job -- letting the metrics half die while the label half survives -- fails
    # this gate.
    "corpus-check":        ["make corpus-check", "CVAP_REQUIRE_LAB"],
    "ci-parity":           ["check_ci_parity.py"],
}

# Targets that deliberately do NOT run in CI. Each needs a reason. Empty today:
# every `ci` prerequisite runs in the workflow.
ALLOWLIST = {
    # "some-target": "why it cannot or should not run in GitHub CI",
}


def ci_prerequisites():
    """The `ci:` prerequisite list, joining backslash continuations."""
    lines = MAKEFILE.read_text().splitlines()
    buf, grab = [], False
    for ln in lines:
        if ln.startswith("ci:"):
            grab = True
        if grab:
            buf.append(ln)
            if not ln.rstrip().endswith("\\"):
                break
    if not buf:
        sys.exit("check_ci_parity: no `ci:` target found in the Makefile")
    logical = " ".join(x.rstrip("\\").strip() for x in buf)
    logical = re.sub(r"##.*", "", logical)
    return logical.split(":", 1)[1].split()


def workflow_haystack():
    """The executable surface of the workflow: the run:, uses: and env: of every
    step and job -- never the comments, which are not what runs."""
    d = yaml.safe_load(WORKFLOW.read_text())
    parts = []

    def add_env(env):
        if isinstance(env, dict):
            for k, v in env.items():
                parts.append(str(k))
                parts.append(str(v))

    for job in d.get("jobs", {}).values():
        add_env(job.get("env"))
        for st in job.get("steps", []):
            if st.get("uses"):
                parts.append(str(st["uses"]))
            if st.get("run"):
                parts.append(str(st["run"]))
            add_env(st.get("env"))
    return "\n".join(parts)


def main():
    prereqs = ci_prerequisites()
    hay = workflow_haystack()
    problems = []

    # Every `ci` target is either mapped to a found signature or allowlisted.
    for t in prereqs:
        if t in ALLOWLIST:
            continue
        sig = SIGNATURES.get(t)
        if sig is None:
            problems.append(
                f"`{t}` is a `make ci` prerequisite with no parity mapping. Add a "
                f"SIGNATURE (the command/action that runs it in .github/workflows/ci.yml) "
                f"or an ALLOWLIST entry with a reason it should not run in CI.")
            continue
        missing = [s for s in sig if s not in hay]
        if missing:
            problems.append(
                f"`{t}` runs in `make ci` but does NOT run in GitHub CI: its signature "
                f"{missing} is absent from the workflow. Add the step to a job in "
                f".github/workflows/ci.yml (a check in the aggregate that the workflow "
                f"never runs is enforced nowhere).")

    # The mapping cannot describe targets that no longer exist.
    known = set(prereqs)
    for t in list(SIGNATURES) + list(ALLOWLIST):
        if t not in known:
            problems.append(
                f"`{t}` has a parity mapping/allowlist entry but is not a `make ci` "
                f"prerequisite any more. Remove the stale entry.")

    if problems:
        print("ci-parity: FAILED — the Makefile `ci` line and the CI workflow disagree",
              file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1

    covered = len(prereqs) - len(ALLOWLIST)
    print(f"ci-parity OK: {len(prereqs)} `ci` targets; {covered} run in the workflow, "
          f"{len(ALLOWLIST)} allowlisted with a reason.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
