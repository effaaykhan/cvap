#!/usr/bin/env bash
# CVAP PostToolUse formatter. Runs after a Go or SQL file is written or edited.
# Never blocks — formatting failures should not stop work.
set -uo pipefail

INPUT=$(cat)
FILE=$(printf '%s' "$INPUT" | python3 -c \
  'import json,sys; d=json.load(sys.stdin); print((d.get("tool_input") or {}).get("file_path",""))' 2>/dev/null)

[ -z "$FILE" ] || [ ! -f "$FILE" ] && exit 0

case "$FILE" in
  *.go)
    command -v gofmt     >/dev/null && gofmt -w "$FILE"
    command -v goimports >/dev/null && goimports -w "$FILE"
    if command -v go >/dev/null; then
      PKG=$(dirname "$FILE")
      OUT=$(go vet "./$PKG" 2>&1) || printf 'go vet:\n%s\n' "$OUT" >&2
    fi
    ;;
  *.py)
    command -v ruff >/dev/null && ruff format -q "$FILE" && ruff check -q --fix "$FILE"
    ;;
  *.sql)
    grep -qi 'CREATE TABLE' "$FILE" 2>/dev/null || exit 0
    if ! grep -qi 'ENABLE ROW LEVEL SECURITY' "$FILE"; then
      echo "WARNING: migration creates a table but has no ENABLE ROW LEVEL SECURITY. If the table is tenant-scoped this is a blocker — see /write-migration." >&2
    fi
    ;;
esac

exit 0
