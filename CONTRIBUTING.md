# Working on CVAP in parallel

Two people, one server, one OS account (`soc`), one clone, one Claude Code
install. This file is how that works without the two of you overwriting each
other.

## The shape

One repository, two **git worktrees**. A worktree is a second checkout backed by
the same `.git`, on its own branch. One directory per person means neither of
you has to stash to let the other build.

```
/home/soc/cvap                 main / feat-core-*   backend, engines, store, correlate
/home/soc/cvap/.worktrees/ui   feat/ui             the operator console
```

The leading dot in `.worktrees/` is load-bearing. Go's `./...` skips directories
beginning with `.`, so the second checkout is invisible to `go build`, `go list`
and `gofmt` — measured: package count and `gosec` file count are identical with
and without it. It is gitignored for the same reason.

Open Claude Code **in the directory you are working in**. It reads `CLAUDE.md`,
`.claude/hooks` and the skills from whichever checkout it is started in, so both
of you get the same project rules, and each gets its own session memory because
Claude keys memory on the directory path.

### Creating or recreating the UI worktree

```bash
cd /home/soc/cvap
git worktree list                       # what exists now
git worktree add .worktrees/ui feat/ui  # if it is missing
```

## Author identity — the bit that makes contributions count

You share an OS account, so you share `~/.gitconfig` and the `gh` credential
helper. GitHub credits a commit to the owner of the **author email**, not to
whoever pushed it, so per-worktree identity is what makes her a contributor.

`extensions.worktreeConfig` is enabled on this repo, which allows exactly that:

```bash
cd /home/soc/cvap/.worktrees/ui
git config --worktree user.name  "Her Name"
git config --worktree user.email "her-github-email@example.com"
```

The email must be one registered on her GitHub account — the private
`…@users.noreply.github.com` address works, if it is the one GitHub issued her.

**Check before the first push, not after:**

```bash
git log -1 --format='%an <%ae>'
```

The main checkout is unaffected; verified — it still reports `effaaykhan`.

## Who owns what

| Area | Owner |
|---|---|
| `internal/control/api/web/**` | frontend |
| everything else | backend |
| `internal/control/api/web/src/api/schema.ts` | **backend** (generated) |

`.github/CODEOWNERS` routes review the same way.

## The one rule that prevents real conflicts

Everything else is separable. The API contract is not.

`src/api/schema.ts` is **generated** from the Go route registry by
`make ui-types`, and the `web` CI job runs `make ui-verify`, which regenerates
it and fails on any diff. Its own comment: *"A route added or reshaped without
regenerating fails HERE."*

So:

1. **Change a route or a response struct → run `make ui-types` and commit the
   regenerated `schema.ts` in the SAME pull request.** Never leave it for the
   frontend to discover.
2. **Never hand-edit `schema.ts`.** On a merge conflict there, do not resolve it
   by hand — regenerate and commit the result.

This is not theoretical. Four fields added to `HealthResponse` without
regenerating left `ui-verify` and the frontend typecheck red for two commits
before anyone ran the gate.

## Branches and pull requests

```
feat/ui-<thing>      frontend
feat/core-<thing>    backend
```

`main` takes pull requests, not direct pushes. CI must be green. Both of you run
the gates locally first — see below — because several of them are slow and CI is
not the place to discover a formatting failure.

**Nothing is pushed without the operator's approval.** That rule predates this
file and still holds: commit locally, report the ahead count, ask.

## Separate databases and ports

Do not share a database. Concurrent test suites against one database interfere —
there is a recorded case of one package's test Core planning another package's
seeded scans.

| | backend | frontend |
|---|---|---|
| dev database | `cvap` | `cvap_fe` |
| test database | `cvap_test` | `cvap_fe_test` |
| Core API | `8445` (TLS) | `8080` (`CVAP_CORE_API_INSECURE=1`) |
| enrol / dispatch | `8443` / `8444` | `8453` / `8454` |
| vite dev server | — | `5173` |

Set hers up once:

```bash
createdb cvap_fe cvap_fe_test                # or: psql -c 'CREATE DATABASE …'
make migrate-up DATABASE_URL=postgres://…/cvap_fe
make app-role   DATABASE_URL=postgres://…/cvap_fe
cvap-cli bootstrap -domain localhost -admin-email admin
```

**`-domain localhost` matters.** `vite.config.ts` proxies `/v1` to
`http://127.0.0.1:8080`, and the proxied Host resolves to `localhost`, which has
to be a real `tenants.domain` row (ADR-041). A tenant bootstrapped with any
other domain refuses the login with *"host resolved to no tenant"*.

## Gates before you push

Backend:

```bash
make lint gosec            # both, always — the one you skip is the one that fails
make store-test            # a bare `go test ./...` SKIPS every database suite
make mutate                # 0 ANCHOR LOST, and the killed count must not drop
```

Frontend:

```bash
make ui                    # ui-verify + typecheck + test + embedui-build
```

Node is **not installed on this host**. The web toolchain runs in the
`node:20-alpine` image that is already present:

```bash
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -e npm_config_cache=/tmp/.npm \
  -v /home/soc/cvap/internal/control/api/web:/w -w /w node:20-alpine \
  sh -c "npx --no-install tsc -b --noEmit && npx --no-install vitest run"
```

`docker` needs `sg docker -c '…'` in a shell whose groups predate the docker
group membership.
