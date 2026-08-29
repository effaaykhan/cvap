#!/usr/bin/env bash
# CVAP PreToolUse guard for frozen contract files.
# proto/ is additive-only within a major version (ADR-022) and accepted ADRs are
# immutable — they get superseded, not edited. Blocks the edit and explains the route.
set -uo pipefail

INPUT=$(cat)
FILE=$(printf '%s' "$INPUT" | python3 -c \
  'import json,sys; d=json.load(sys.stdin); print((d.get("tool_input") or {}).get("file_path",""))' 2>/dev/null)

[ -z "$FILE" ] && exit 0

case "$FILE" in
  */proto/*.proto)
    cat >&2 <<'MSG'
BLOCKED: proto/ is the frozen wire contract (ADR-022).

Scan points in customer networks run months-old builds, so changes must be
additive-only within a major version: no field removal, no renumbering, no
changed semantics for an existing field.

If the change is genuinely additive, remove this guard for one edit by setting
CVAP_ALLOW_PROTO_EDIT=1 in the environment, and record the addition in the ADR.
If it is not additive, it needs a major version and a migration plan first.
MSG
    [ "${CVAP_ALLOW_PROTO_EDIT:-0}" = "1" ] && exit 0
    exit 2
    ;;
  */docs/adr/*.md)
    case "$FILE" in
      */000-index.md) exit 0 ;;
    esac
    if grep -qi '^\*\*Status:\*\* *Accepted' "$FILE" 2>/dev/null; then
      cat >&2 <<'MSG'
BLOCKED: this ADR is Accepted. Accepted decisions are superseded, not edited.

Write a new ADR that supersedes it, then set the old one's status to
"Superseded by ADR-NNN". Use /new-adr to scaffold it.
MSG
      exit 2
    fi
    ;;
esac

exit 0
