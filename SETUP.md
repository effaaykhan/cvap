# CVAP — Claude Code configuration

A working set of skills, subagents, hooks and memory files for building CyberSentinel.
Drop it into the repo root, commit it, and it applies to every session.

Verified against the current Claude Code docs for [skills](https://code.claude.com/docs/en/skills)
and [subagents](https://code.claude.com/docs/en/sub-agents) as of August 2026.

---

## Install

```bash
cd /path/to/cvap
cp -r cvap-config/. .
chmod +x .claude/hooks/*.sh .claude/hooks/*.py
git add CLAUDE.md .claude docs lab internal && git commit -m "claude code config"
```

Restart Claude Code afterwards. The watcher only covers directories that existed when the
session started, so a brand-new `.claude/agents/` or `.claude/skills/` needs a restart to
be seen. Edits after that are picked up live.

Verify with `/doctor`, then `/skills` and `@` in the prompt to confirm the agents load.

---

## Why it is shaped this way

Four primitives, four jobs. Most messy setups come from using the wrong one.

| Primitive | Job | Cost |
|---|---|---|
| **CLAUDE.md** | Always-true facts. Layout, commands, non-negotiables | In context every session — keep it short |
| **Skills** | Procedures loaded on demand | Description always in context, body only when invoked |
| **Subagents** | Work whose output shouldn't pollute the main thread | Description in context, own window |
| **Hooks** | Things that must happen regardless of what Claude decides | None |

The mapping matters here specifically because the execution plan named codebase coherence
across sessions as a live risk, and because a security product written mostly by an AI with
one reviewer needs compensating controls that don't depend on anyone remembering.

**Rules that must hold go in hooks, not prose.** An invariant written in CLAUDE.md is a
suggestion that competes for attention with everything else in context. The scope guard,
the contract freeze and the RLS warning are hooks because they need to fire whether or not
the model is paying attention.

---

## What's here

```
CLAUDE.md                                  root memory — short by design
internal/domain/CLAUDE.md                  per-module contracts
internal/scanpoint/CLAUDE.md
internal/engines/CLAUDE.md
.claude/settings.json                      hooks + permissions
.claude/hooks/lab-scope-guard.py           blocks scans outside lab/scope.txt
.claude/hooks/protect-contracts.sh         freezes proto/ and accepted ADRs
.claude/hooks/go-fmt-lint.sh               fmt, vet, RLS warning on migrations
.claude/agents/security-reviewer.md
.claude/agents/scan-safety-auditor.md
.claude/agents/schema-auditor.md
.claude/agents/adr-compliance.md
.claude/agents/test-runner.md
.claude/skills/cvap-invariants/            the hard rules
.claude/skills/write-migration/
.claude/skills/write-detection-rule/
.claude/skills/add-scan-engine/
.claude/skills/new-adr/
.claude/skills/safety-gate/
.claude/skills/weekly-checkpoint/
lab/scope.txt                              the allowlist the guard reads
docs/adr/000-index.md                      the 23 decisions from the plan
```

---

## The hooks

### `lab-scope-guard.py` — the important one

Blocks any Bash command that points a scanning tool at an address outside `lab/scope.txt`.
You are about to spend eight weeks repeatedly running a port scanner to test it. One
careless target, one copy-pasted range, and you have committed a criminal offence in most
jurisdictions. This closes that gap deterministically.

Behaviour:

- Recognises scan tools (`cvap-*`, nmap, masscan, zmap, nuclei, hping, sslscan, sqlmap, and
  others) plus soft tools (curl, wget) where only literal IPs are judged.
- Extracts every IPv4 and IPv6 literal and checks it against the allowlist.
- Blocks a scan tool reading targets indirectly from a file or variable, since it cannot
  evaluate those.
- Defaults to loopback, RFC1918, link-local, CGNAT and the reserved documentation ranges
  when `lab/scope.txt` is absent.

Tested against seventeen cases. `nmap 192.168.56.101` and `curl https://proxy.golang.org`
pass; `cvap-cli scan 8.8.8.8`, `masscan 0.0.0.0/0`, `nmap -iL targets.txt` and
`curl http://45.33.32.156/` are blocked.

This is a development guardrail, not the product's scope enforcement. The real one is the
policy engine plus the `make safety` egress-capture suite, and neither is replaced by this.

### `protect-contracts.sh`

Blocks edits to `proto/*.proto` and to accepted ADRs. The protocol is additive-only because
scan points in customer networks run months-old builds; accepted decisions get superseded,
not rewritten. Proto edits can be allowed for one command with `CVAP_ALLOW_PROTO_EDIT=1`,
which is deliberately slightly annoying.

### `go-fmt-lint.sh`

Runs `gofmt`, `goimports` and `go vet` on touched Go files, `ruff` on Python, and warns
when a migration creates a table without enabling RLS. Never blocks.

---

## The subagents

Five, each read-only except `test-runner`, all returning a summary rather than a transcript.
Descriptions are kept short because they sit in context every session — Claude Code warns
past 15,000 tokens of combined agent descriptions.

| Agent | Model | Use |
|---|---|---|
| `security-reviewer` | opus | CVAP's own security: tenancy, authz, credentials, parsers, deps |
| `scan-safety-auditor` | opus | Whether the scanner can misbehave: scope, rate, blast radius |
| `schema-auditor` | sonnet | Migrations against the data-model invariants |
| `adr-compliance` | opus | Architecture drift and contract disagreement between modules |
| `test-runner` | haiku | Runs suites, returns failures only |

`security-reviewer` and `scan-safety-auditor` look superficially similar and are not. The
first asks whether CVAP can be attacked; the second asks whether CVAP can damage someone
else's network. Different checklists, different failure modes, both needed.

The three reviewers preload `cvap-invariants` via the `skills:` field, so they start with
the rules in context instead of hunting for them. `security-reviewer`,
`scan-safety-auditor` and their peers also use `memory: project`, which gives them
`.claude/agent-memory/<name>/` to accumulate recurring findings across sessions. Commit
that directory — it is how the reviewers get better over eight weeks rather than starting
cold each time.

---

## The skills

`cvap-invariants` is the one that does the work. It is the hard rules with no prose:
observation-first flow, identity key ranking, dedup keys per source, RLS and partitioning,
protocol versioning, lease semantics, credential handling, rate ceilings, advisory-first
matching. Everything else references it.

`write-migration`, `write-detection-rule` and `add-scan-engine` are procedures. The first
two use `paths:` so they only auto-activate when the relevant files are in play, which
keeps them from firing on unrelated work.

`new-adr`, `safety-gate` and `weekly-checkpoint` set `disable-model-invocation: true` —
you invoke them, Claude does not. They have side effects or cost real time, and the model
should not decide when to spend either. `safety-gate` and `weekly-checkpoint` use
`` !`command` `` injection so live output is in the prompt before Claude reads it.

---

## Working rhythm

**Per change.** Write it. `schema-auditor` if a migration was touched. `scan-safety-auditor`
if anything can send a packet. `security-reviewer` if auth, tenancy, credentials or
dependencies moved. `test-runner` for the suite.

**Before merge.** `/safety-gate`. It is a hard gate, not advice — a failure means the
scanner could touch something unauthorised.

**Weekly.** `/weekly-checkpoint <n>`. It reads the plan's week-N deliverable and the frozen
MVP scope, and tells you plainly whether you met it and whether you built something you
said you would not. The plan has no buffer, so an unflagged slipped week is the whole
schedule.

**Per decision.** `/new-adr`. Twenty-three are already indexed; you will add more, and the
`adr-compliance` agent is only as good as the record.

---

## Two things worth adding later

**A read-only Postgres MCP server** pointed at the dev database, so Claude can inspect the
live schema and run `EXPLAIN` rather than inferring from migration files. Scope it read-only
and to the dev database only. Define it in a subagent's `mcpServers` frontmatter rather than
`.mcp.json` if you want the tool descriptions out of the main context.

**`claude plugin validate .claude/agents`** in CI. It catches frontmatter that fails to
parse, which otherwise fails silently — Claude Code skips a malformed agent file and only
writes the reason to the debug log.

---

## Where this doesn't help

The plan listed things no configuration removes: design partner network access, detection
content curation, fingerprint signatures from real devices, the customer authorization
contract, SOC 2 evidence, external security review, and the judgment call about when the
product is good enough to charge for.

The reviewers in here are a compensating control for a thin review layer. They are not a
substitute for a human security review before the first customer, which is risk 4 in the
plan and still needs doing.
