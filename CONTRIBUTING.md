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

### The directory decides the author, and a hook enforces it

A commit made in the UI worktree carrying the backend identity is silently
mis-credited, and it is only visible once it reaches GitHub. `.git/hooks/pre-commit`
refuses it instead: it reads `git rev-parse --show-toplevel` and checks the
author against that directory's owner, printing the one-line fix. Tested three
ways — worktree with her identity allowed, worktree with his REFUSED, main with
his allowed.

So: **backend work is committed in `/home/soc/cvap`, console work in
`.worktrees/ui`, and neither crosses over.** If you need to move a file between
the two, move it with a merge, not by editing it in the other directory.

`.git/hooks` is outside the tree, so the hook does not survive a fresh clone or
a worktree recreated elsewhere. Reinstall it if either happens, or
mis-attribution goes back to being silent.

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

---

# Merging the UI worktree into the main checkout

Changes made in `.worktrees/ui` do **not** appear in `/home/soc/cvap` on their
own. They are two checkouts on two branches; you bring the work across
deliberately.

## 0. See where you stand

```bash
cd /home/soc/cvap
git worktree list
git rev-list --left-right --count main...feat/ui   # "X Y" = main ahead X, ui ahead Y
```

Second number `0` means there is nothing to merge.

## 1. Commit, in the worktree

Uncommitted work does not merge.

```bash
cd /home/soc/cvap/.worktrees/ui
git status --short
git add <files> && git commit -m "UI: ..."
```

## 2. Gate it, in the worktree

```bash
make ui     # ui-verify + typecheck + test + embedui-build
```

Node is not installed on this host. If `npx` is missing, run the gate in the
container:

```bash
sg docker -c 'docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -e npm_config_cache=/tmp/.npm \
  -v /home/soc/cvap/.worktrees/ui/internal/control/api/web:/w -w /w node:20-alpine \
  sh -c "npx --no-install tsc -b --noEmit && npx --no-install vitest run"'
```

Fix failures here, not after merging.

## 3. Rebase onto main — the step people skip

```bash
git rebase main
```

This pulls backend changes in and surfaces conflicts in HER tree, where they are
hers to resolve. Skip it and her conflicts land in your directory instead.

**If `src/api/schema.ts` conflicts, do not resolve it by hand.** It is
generated. Take either side, then regenerate and re-run the gate:

```bash
git checkout --theirs internal/control/api/web/src/api/schema.ts
cd /home/soc/cvap && make ui-types
```

## 4. Merge into the main checkout

`-C` targets the other directory without leaving this one:

```bash
git -C /home/soc/cvap merge feat/ui --no-edit
git -C /home/soc/cvap log --oneline -2
```

After step 3 this is always a fast-forward. The files are now in
`/home/soc/cvap` — **and the running dashboard has not changed.**

## 5. Rebuild — the other step people skip

The console is compiled INTO `cvap-core` under the `embedui` tag, so a merge
alone changes nothing that is served.

```bash
cd /home/soc/cvap

# bundle
sg docker -c 'docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -e npm_config_cache=/tmp/.npm \
  -v /home/soc/cvap/internal/control/api/web:/w -w /w node:20-alpine npx --no-install vite build'

# relink
go build -tags embedui -o <bin-dir>/cvap-core ./cmd/cvap-core

# restart: stop the old process, start the new binary with the same environment
ps -eo pid,comm | grep cvap-core        # find the pid
kill <old-pid>
<same env vars as before> setsid nohup <bin-dir>/cvap-core > <log> 2>&1 &
```

## 6. Verify it took

Do not trust the restart — check the bytes the server hands out. The bundle
filename carries a content hash, so a changed hash proves new code is being
served:

```bash
curl -sk https://<host>:8445/ | grep -oE 'index-[A-Za-z0-9_-]+\.js'
curl -sk https://<host>:8445/assets/index-<hash>.js | grep -c '<a string from your change>'
```

The hash must differ from before, and the count must be `1`.

## 7. Push

```bash
git -C /home/soc/cvap push origin main     # or open a PR from feat/ui
```

Nothing is pushed without the operator's approval.

---

**Short version:** commit → `make ui` → `git rebase main` →
`git -C /home/soc/cvap merge feat/ui` → rebuild → restart → check the hash.
Steps 3 and 5 are the ones that get skipped: skipping 3 moves her conflicts into
your directory, skipping 5 leaves you looking at the old dashboard wondering why
nothing changed.
