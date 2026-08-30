#!/usr/bin/env python3
"""Validate the YAML frontmatter on Claude Code agents and skills.

The failure mode this catches is silent: a malformed agent or skill file is
skipped at load time rather than reported, so the review subagent you think is
running simply is not. That is worth a CI job.

Checks every .claude/agents/*.md and .claude/skills/**/SKILL.md for:
  - a frontmatter block delimited by --- at the top of the file
  - frontmatter that parses as YAML
  - a non-empty `name` and `description`
  - `name` matching the filename (agents) or directory (skills), since a
    mismatch means you invoke one thing and get another

Exits 1 on any failure, listing every problem rather than the first.
"""

from __future__ import annotations

import pathlib
import sys

try:
    import yaml
except ImportError:
    print("PyYAML is required: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

ROOT = pathlib.Path(__file__).resolve().parents[2]


def split_frontmatter(text: str) -> str | None:
    """Return the raw frontmatter block, or None if absent/unterminated."""
    if not text.startswith("---"):
        return None
    lines = text.splitlines()
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            return "\n".join(lines[1:i])
    return None


def check(path: pathlib.Path, expected_name: str, errors: list[str]) -> None:
    rel = path.relative_to(ROOT)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        errors.append(f"{rel}: unreadable: {exc}")
        return

    raw = split_frontmatter(text)
    if raw is None:
        errors.append(f"{rel}: no frontmatter block (file must open with --- and close with ---)")
        return

    try:
        meta = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        errors.append(f"{rel}: frontmatter is not valid YAML: {exc}")
        return

    if not isinstance(meta, dict):
        errors.append(f"{rel}: frontmatter must be a mapping, got {type(meta).__name__}")
        return

    for field in ("name", "description"):
        value = meta.get(field)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{rel}: missing or empty `{field}`")

    name = meta.get("name")
    if isinstance(name, str) and name.strip() and name.strip() != expected_name:
        errors.append(
            f"{rel}: name is {name.strip()!r} but this file is loaded as {expected_name!r}"
        )


def main() -> int:
    errors: list[str] = []
    checked = 0

    agents_dir = ROOT / ".claude" / "agents"
    for path in sorted(agents_dir.glob("*.md")):
        check(path, path.stem, errors)
        checked += 1

    skills_dir = ROOT / ".claude" / "skills"
    for path in sorted(skills_dir.glob("*/SKILL.md")):
        check(path, path.parent.name, errors)
        checked += 1

    if not checked:
        print("No agent or skill files found — expected at least one.", file=sys.stderr)
        return 1

    if errors:
        print(f"Frontmatter validation failed ({len(errors)} problem(s)):", file=sys.stderr)
        for err in errors:
            print(f"  {err}", file=sys.stderr)
        return 1

    print(f"Frontmatter OK: {checked} file(s) checked.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
