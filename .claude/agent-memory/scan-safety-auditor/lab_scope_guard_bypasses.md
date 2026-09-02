---
name: lab-scope-guard-bypasses
description: Confirmed ways a Bash command reaches an out-of-scope address past .claude/hooks/lab-scope-guard.py — re-test these on any guard change
metadata:
  type: project
---

`.claude/hooks/lab-scope-guard.py` implements CLAUDE.md non-negotiable 10. Confirmed by
running the guard directly on 2026-09-02 (probe fed JSON on stdin, no packets sent, target
198.18.0.1 chosen because RFC 2544 benchmarking space is reserved and unrouted).

**Allowed when they should be blocked:**

1. **Quoting.** `SCAN_TOOLS`'s prefix class is `[\s;&|(/.]`. It has no `'`, `"`, `` ` `` or
   `=`, so `bash -c "nmap X"`, `sh -c 'nmap X'`, `` echo `nmap X` `` and `CMD=nmap $CMD X` all
   pass. This is the largest hole and it sits in the character class the guard has been tuned
   twice already.
2. **Hostnames.** A hard scan tool with a hostname target and no literal IP is allowed:
   `targets()` finds nothing, and `looks_indirect` only fires on `-i`, `--target`, `--input`,
   `$var`, `<` or `cat`. The module docstring says soft tools object to IPs "not to hostnames",
   implying hard tools do — they do not.
3. **Non-dotted-quad encodings.** `nmap 3323068417`, `nmap 0xC6120001` and
   `nmap 0198.0018.0000.0001` all pass `IP_TOKEN`. The block message tells the reader not to
   "encode the address differently"; the guard does not detect it when they do.
4. **Anything not in the tool list that opens a socket.** `go test ./... -args -target X` and
   `python3 -c "socket.create_connection(...)"` are allowed. The list is binaries, and the
   deliverable is any process that dials.

**Correctly blocked** (do not regress): literal out-of-scope v4, v4-mapped v6
(`::ffff:198.18.0.1`), `X=<ip>; nmap $X`, and — new since the `/` and `.` were added to the
prefix class — `./cvap-scanpoint <ip>` and `go run ./cmd/cvap-scanpoint <ip>`. That addition
was a real improvement and closed the most natural way to run a locally built binary.

**How to apply:** this is a *development* control, not a product one, so weigh it against
false positives — the file's own comments record that a guard people route around stops being
a guard, and `cvap` was removed from the tool list because it matched the `psql -U cvap`
database role. Fixing 1 (add quote characters) is cheap and low-false-positive. Fixing 2 and 3
raises false positives and should be argued for, not assumed.

Related: [[dispatch-scope-and-kill-gaps]]
