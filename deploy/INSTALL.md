# Installing CVAP on a single node

This brings up a whole CVAP control plane on one host with Docker Compose —
PostgreSQL, MinIO, the schema, the application role, and `cvap-core` — and walks
the enrollment flow from first boot to a scan point submitting a result.

Compose-first is the primary deployment target (ADR-023), not a convenience. The
dev stack at the repository root runs the data layer only; this runs everything.

It documents what the system **does**. Where a step is a limitation rather than a
feature, it says so, and the plainly-named limitations are collected in
[the operator runbook](../docs/runbook.md#known-limitations).

---

## 1. Prerequisites

- Docker Engine with the Compose plugin (`docker compose`, not `docker-compose`).
- **Permission to run Docker without sudo.** Every command here calls `docker`.
  If `docker ps` gives "permission denied … /var/run/docker.sock", add yourself to
  the `docker` group once — `sudo usermod -aG docker "$USER"` — then open a new
  login shell (or `newgrp docker`) so the membership takes effect. Otherwise
  prefix every `docker` command with `sudo`, and set `CVAP_UID`/`CVAP_GID` (below)
  to the user that will OWN `deploy/secrets`, not to root.
- A trust anchor: a CA certificate and key at `deploy/secrets/ca.crt` and
  `deploy/secrets/ca.key`, mode `0600` on the key, and **owned by the UID the
  cvap-core container runs as** — see `CVAP_UID`/`CVAP_GID` in §2, which exist
  because the image runs nonroot and the CA loader refuses a key any wider than
  `0600`, so the key's owner and the container's user have to be the same person.
  This CA mints every scan point's identity, so its key is the whole compromise
  if it leaks (architecture-v2 §18.3); it is mounted read-only, never baked in.
  - **Production:** supply your organisation's CA keypair.
  - **Evaluation only:** generate a throwaway pair with the image's own CLI (no
    local build needed), owned by you, after `docker compose build cvap-core`.
    `--valid-for 720h` makes it last a 30-day evaluation rather than expire
    mid-review; it is still a development CA (capped at 90 days), never a real
    anchor:

    ```sh
    mkdir -p deploy/secrets
    docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/deploy/secrets:/secrets" \
      --entrypoint /usr/local/bin/cvap-cli cvap-deploy-cvap-core dev-ca --valid-for 720h /secrets
    ```

    **To regenerate** when it expires — same command, after clearing the old
    pair (`rm -f deploy/secrets/ca.crt deploy/secrets/ca.key`), then restart Core
    (`docker compose up -d --force-recreate cvap-core`). Enrolled scan points were
    issued by the old CA and must re-enrol against the new one; existing scan data
    is unaffected.

All commands below are run from the `deploy/` directory.

---

## 2. Configure

```sh
cd deploy
cp env.example .env
```

Edit `.env` and set every `CHANGE-ME` secret and `CVAP_ADVERTISE_HOST`. That last
one is the address a scan point uses to reach this host — a DNS name or LAN IP,
never `localhost` or a container name — because Core hands it to a scan point at
enrollment. `.env` is gitignored and must never be committed.

Also set `CVAP_UID` and `CVAP_GID` to the user that owns `deploy/secrets` — your
`id -u` and `id -g`. cvap-core runs as this user so it can read the `0600` CA key
(the image is nonroot, and the key must be owned by whoever the container runs
as; the default `65532` is for a deployment that provisions secrets to the
nonroot user directly).

---

## 3. Bring up the stack

```sh
docker compose up -d --build
```

On first boot the one-shot services run in order and exit:

1. **postgres**, **minio** — the data layer, on the compose network only. The
   database is deliberately not published to the host.
2. **createbuckets** — creates the evidence bucket in MinIO.
3. **migrate** — applies every migration as the migration role, creating the
   `cvap_app` group role, the schema, RLS policies and grants.
4. **provision** — creates `cvap_app_login`, the LOGIN role `cvap-core` connects
   as. It holds neither `BYPASSRLS` nor `SUPERUSER`, so RLS applies to it
   (ADR-002); the provisioning SQL asserts this and fails the deploy otherwise.
5. **cvap-core** — the control plane, once 3 and 4 have completed.

Check it came up:

```sh
docker compose ps
docker compose logs cvap-core | tail
```

`cvap-core` logs three listeners: enrollment (`:8443`, server TLS), dispatch +
ingest (`:8444`, mTLS) and the operator API (`:8445`, server TLS + session).

---

## 4. Bootstrap the first tenant and admin

There is no operator to authenticate yet, so the first tenant is created with a
CLI one-shot against the database — the one operator action that legitimately
predates authentication.

```sh
docker compose run --rm \
  -e APP_DATABASE_URL="postgres://cvap_app_login:${APP_ROLE_PASSWORD}@postgres:5432/${POSTGRES_DB}?sslmode=disable" \
  --entrypoint /usr/local/bin/cvap-cli \
  cvap-core bootstrap --admin-email you@example.com --domain "$CVAP_EXTERNAL_HOST"
```

(`${APP_ROLE_PASSWORD}`, `${POSTGRES_DB}` and `$CVAP_EXTERNAL_HOST` come from your
shell if you `set -a; . ./.env; set +a` first, or paste the values.)

`--domain` is **required and has no default**: it must be the host operators will
actually reach the API at — the same address as `CVAP_EXTERNAL_HOST` — because the
tenant is resolved from the request `Host` (ADR-041). Use `localhost` only for a
loopback-only install. Getting this wrong does not fail here in a way you would
notice later: it fails at *first login* with a 401 that looks like a bad password.
If it is already wrong, or the address changes, correct it with
`cvap-cli tenant set-domain --tenant <id> --domain <host>` (audited) rather than
re-bootstrapping.

It prints, once, the created ids and a **generated first-login password**:

```
initial admin password (must be changed on first login): <captured here>
```

Capture the password and the printed `zone_id` — you need both. Bootstrap ends by
verifying its own login and refuses to report success otherwise, and running it a
second time for the same domain is refused — it is not an editing tool.

Local login also requires `CVAP_CORE_LOCAL_AUTH=1` (the compose default). It is a
Core-wide flag, not a per-tenant one: that is the control, so a tenant admin
cannot opt their tenant out of an SSO policy on their own.

---

## 5. Issue an enrollment token

```sh
docker compose run --rm \
  -e APP_DATABASE_URL="postgres://cvap_app_login:${APP_ROLE_PASSWORD}@postgres:5432/${POSTGRES_DB}?sslmode=disable" \
  --entrypoint /usr/local/bin/cvap-cli \
  cvap-core enroll-token --tenant <TENANT_ID> --zone <ZONE_ID> --description "first scan point"
```

It prints, once:

```
enrollment token (shown once): cvapent_...
```

The token is single-use and TTL-bounded (24 h by default, 7 days maximum). It is
not recoverable — the database stores only a hash — so if you lose it, issue
another. Write it to a file for the scan point (never an environment variable — a
token in `/proc/<pid>/environ` is inherited by every child, including engines):

```sh
umask 077
printf '%s' 'cvapent_...' > secrets/enrollment-token
```

---

## 6. Start a scan point

A scan point is not a compose service, because it cannot come up until a token
exists. Run it from the same image, pointed at this host's enrollment endpoint:

The scan point must be on the **compose network** (to reach `cvap-core`) and be
able to reach the hosts it will scan. The compose network is `<project>_default`
— `cvap_default` for the default project name. It runs as the same UID as the
secrets it reads, and its data dir (where it writes its issued certificate) must
be writable by that UID, so use a host directory you own rather than a fresh
named volume:

```sh
mkdir -p "$PWD/scanpoint-data"
docker run -d --name cvap-scanpoint \
  --network cvap_default \
  --user "$(id -u):$(id -g)" \
  -v "$PWD/secrets/ca.crt:/creds/ca.crt:ro" \
  -v "$PWD/secrets/enrollment-token:/creds/enrollment-token:ro" \
  -v "$PWD/scanpoint-data:/data" \
  -e CVAP_SP_ENROLL_ENDPOINT="${CVAP_ADVERTISE_HOST}:8443" \
  -e CVAP_SP_CA_BUNDLE=/creds/ca.crt \
  -e CVAP_SP_ENROLLMENT_TOKEN_FILE=/creds/enrollment-token \
  -e CVAP_SP_DATA_DIR=/data \
  -e CVAP_SP_ENGINE_BINARIES=/usr/local/bin/cvap-engine-discovery,/usr/local/bin/cvap-engine-fingerprint \
  --entrypoint /usr/local/bin/cvap-scanpoint \
  cvap-cvap-core
```

(`cvap-cvap-core` is the image compose built; adjust if your project name
differs. If the scan point must reach a target network the compose network does
not, `docker network connect <that-network> cvap-scanpoint` after it starts.)

On start it reads the token, redeems it against the enrollment endpoint, receives
a certificate and its dispatch/ingest/rule-pack endpoints, zeroises the token,
and begins leasing jobs.

**This is the end of the install path: an enrolled, connected scan point.**
Confirm it — the log shows `enrolled` then `connected`:

```sh
docker logs cvap-scanpoint
```

and, once you are logged in (§7), it appears in the fleet as `"health":"healthy"`:

```sh
curl -sS --cacert secrets/ca.crt -b cookies.txt https://localhost:8445/v1/scan-points
```

Everything below (§7–§8) is running an actual scan through that scan point, which
you need before the operator UI screens have anything to show.

---

## 7. Log in, then run a scan

The operator API is authenticated with a session cookie and a CSRF header. The
server certificate is signed by your CA, so pass `--cacert`. The request **Host**
must match the tenant's domain (`localhost` from step 4).

```sh
# Log in. Returns a csrf_token and sets the session + csrf cookies.
curl -sS --cacert secrets/ca.crt -c cookies.txt https://localhost:8445/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"<bootstrap password>"}'
```

The response has `"must_change_password": true`. Until you change it, every
endpoint except the password change refuses the session:

```sh
CSRF=<csrf_token from the login response>
curl -sS --cacert secrets/ca.crt -b cookies.txt -c cookies.txt \
  -X POST https://localhost:8445/v1/auth/password \
  -H "X-CVAP-CSRF: $CSRF" -H 'Content-Type: application/json' \
  -d '{"current_password":"<bootstrap password>","new_password":"<a new one, 12+ chars>"}'
```

Log in again with the new password to get a fresh `csrf_token`, then:

```sh
# Authorise a range in the zone. The attestation is not a formality — planning
# refuses a target that is not attested (execution-plan §8, risk 6).
curl -sS --cacert secrets/ca.crt -b cookies.txt -X POST \
  https://localhost:8445/v1/zones/<ZONE_ID>/ranges \
  -H "X-CVAP-CSRF: $CSRF" -H 'Content-Type: application/json' \
  -d '{"prefix":"192.0.2.0/24","authorization_verified":true}'

# Create a policy (safe is the default ceiling; intrusive is a separate opt-in).
curl -sS --cacert secrets/ca.crt -b cookies.txt -X POST \
  https://localhost:8445/v1/policies \
  -H "X-CVAP-CSRF: $CSRF" -H 'Content-Type: application/json' \
  -d '{"name":"baseline","safety_mode":"safe","time_windows":[],"allowed_engines":[],"allowed_zones":[]}'

# Add an ALLOW scope rule to the policy. This is separate from the zone range
# above and easy to miss: the zone range gates whether planning ACCEPTS a target,
# but a job's on-the-wire allowlist comes from the policy's scope rules, and an
# empty allowlist denies everything (ADR-037). Without this every job is refused
# with scope_violation_halt and the scan produces nothing.
curl -sS --cacert secrets/ca.crt -b cookies.txt -X POST \
  https://localhost:8445/v1/policies/<POLICY_ID>/scope-rules \
  -H "X-CVAP-CSRF: $CSRF" -H 'Content-Type: application/json' \
  -d '{"effect":"allow","match_type":"cidr","match_value":"192.0.2.0/24"}'

# Create a scan against an attested target. It is refused (422) unless a scan
# point capable of this engine is online in a zone the policy permits — so run it
# after §6, not before.
curl -sS --cacert secrets/ca.crt -b cookies.txt -X POST \
  https://localhost:8445/v1/scans \
  -H "X-CVAP-CSRF: $CSRF" -H 'Content-Type: application/json' \
  -d '{"policy_id":"<POLICY_ID>","scan_type":"discovery","targets":[{"type":"cidr","value":"192.0.2.0/24","authorization_verified":true}]}'
```

Core plans the scan into jobs, dispatch leases them to the enrolled scan point,
its engines run, and it submits **observations** — a scan point never writes
assets or findings itself (that is Core's job, ADR-006).

---

## 8. Read the result

Correlation turns observations into assets, and the finding pipeline turns
attested evidence into findings, both on a periodic cycle a minute or two after
ingest.

```sh
curl -sS --cacert secrets/ca.crt -b cookies.txt https://localhost:8445/v1/scans/<SCAN_ID>
curl -sS --cacert secrets/ca.crt -b cookies.txt https://localhost:8445/v1/assets
curl -sS --cacert secrets/ca.crt -b cookies.txt https://localhost:8445/v1/findings
```

When assets and findings appear for the scanned range, the flow is complete:
token to enrolled scan point to observations to a finding an operator can read.

---

## 9. Scope, day two, and what is not here

- **Scope discipline.** Only attested ranges and targets are scanned; planning
  refuses the rest. In a development checkout a second guard blocks anything
  outside `lab/scope.txt` — that guard is for development and does not gate a
  deployment, where the attestation and the policy ceilings are the enforcement.
- **Operations** — the two-place OIDC disable, safe-mode versus intrusive
  escalation, the kill switch and `expected_ack_count`, reading scan-point health
  — are in [the operator runbook](../docs/runbook.md).
- **Not in the CLI.** `cvap-cli` does `bootstrap` and `enroll-token` only.
  Creating further users, roles, zones and tenants is done through the
  authenticated API; a management CLI is deferred (execution-plan §6.5).
- **Known limitations** (no CVE matching, no credentialed assessment, and more)
  have [their own section in the runbook](../docs/runbook.md#known-limitations).
