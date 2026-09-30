# auth-console

The identity console of a Yundera PCS or a FOSS (NSL.sh) mesh box: who can sign in, and
who can reach the host. It is the web UI of the **`auth` stack** — Dex, Authelia and
auth-registrar — and replaces the **Account** and **Access** panels of
`settings-center-app` (the Yundera admin app).

Served at `auth-console-${DOMAIN}` (plus the `nip.io` / `sslip.io` variants), behind an
AppShield gate. The **Auth** tile in Maison opens it.

See [architecture.md](./architecture.md) for the design and
[implementation_note.md](./implementation_note.md) for decisions, rollout and known gaps.

## Pages

| Page | Who | Shows | Acts |
|---|---|---|---|
| **Account** | every signed-in user | Name, username, email, role; link to Authelia's portal (`local-auth-${DOMAIN}`) for password change, reset-by-email and TOTP | Sign out |
| **Account › Local accounts** | admins | Authelia users: username, display name, email, role, owner / disabled | Add user (one-time password), change email, reset password (one-time password), revoke. Revoke and reset end the user's sessions on this console |
| **Account › Onboarding** | admins, Yundera only | Claimed / unclaimed, owner name | — (reset is terminal-only: `onboarding.sh reset --confirm`) |
| **Access** | admins | Host Linux accounts, their `authorized_keys` (tagged admin app / support / user / unknown), last 50 logins | Add a key (paste, or generate an Ed25519 pair in the browser — the private key never leaves it), remove a key, consent screen for `/access?account=&pubkey=` / `&pubkeyUrl=` deep links |
| **Access › Support access** | admins, Yundera only | Intended vs actual state of the operator's support key | Enable / disable (with a lockout warning) |

"Yundera only" sections appear when the matching host script exists and `OPERATOR_API` is
set; a FOSS box simply does not show them. Claiming the login stays on the command line
(`install.sh --claim-*`, or `authelia-user-manager.sh claim` over SSH).

## How it works

```
browser ─► mesh-router-caddy ─► auth-console (AppShield gate)
                                    │  X-AppShield-Assertion (HS256, aud auth-console)
                                    ▼
                              auth-console-app (this image)
                    ├─ reads  /host-root = the platform root, read-only (.env, which scripts exist)
                    ├─ docker socket: one-shot auth-console-runner, nsenter into the host →
                    │     authelia-user-manager.sh, onboarding.sh status, feature-support-key.sh,
                    │     fixed authorized_keys scripts
                    ├─ HTTP:  POST http://auth-console/nhl-auth/sessions/revoke
                    └─ HTTPS: ${OPERATOR_API}/support/ssh-key, pubkeyUrl deep links (SSRF-guarded)

same stack:  dex (auth-${DOMAIN}) ◄─ authelia (local-auth-${DOMAIN}) · auth-registrar (:9092, internal)
```

- **Auth.** Every `/api/*` route except `/api/health` requires a valid
  `X-AppShield-Assertion` (issuer `appshield`, audience `auth-console`, signed with
  `IDENTITY_ASSERTION_SECRET`) for an interactive login (machine methods are refused).
  Plain `Remote-*` / `X-Auth-Request-*` headers are ignored — any container on `pcs` can
  reach the app directly. The gate does **not** set `OIDC_REQUIRED_GROUPS`: every user may
  reach their own Account page; admin routes check the `admins` (or `admin`) group in the
  app. No secret configured → every request is refused. Non-GET requests need
  `X-Auth-Console: 1` (CSRF).
- **Host actions** run in a one-shot privileged `auth-console-runner` container created
  from this image, `nsenter -t 1 -m -u -i -n -p` into the host. Fixed argv per verb, user
  input only in validated positional arguments, one at a time (queued in-process). No
  SSH, no sudoers, no generic command endpoint.
- **Accounts** are changed only through the template's own `authelia-user-manager.sh`
  (flock, atomic write, argon2 via the Authelia image) — this app never writes
  `users_database.yml`.

## Configuration

| Env | Default | |
|---|---|---|
| `IDENTITY_ASSERTION_SECRET` | — | Required. Same value as the gate's |
| `IDENTITY_ASSERTION_AUDIENCE` | `auth-console` | Must equal the gate's `APP_NAME` (its hostname) |
| `APPSHIELD_GATE_URL` | `http://auth-console` | Where session revocation is sent |
| `HOST_ROOT` | — | Required. The platform root as the host sees it: `/DATA/AppData/yundera` or `/DATA/AppData/mesh` |
| `HOST_SCRIPTS` | detected | Host scripts dir. Default `$HOST_ROOT/template/scripts` when it holds `tools/authelia-user-manager.sh`, else `$HOST_ROOT/scripts` |
| `HOST_ROOT_MOUNT` | `/host-root` | Where `HOST_ROOT` is mounted read-only in this container |
| `OPERATOR_API` | — | Yundera only. Enables the support-key tag and toggle |
| `TRUSTED_PUBKEY_HOST_SUFFIXES` | — | CSV; deep-link keys fetched from these hosts are shown as "trusted" |
| `LOCAL_AUTH_URL` | `https://local-auth-${DOMAIN}` | The "Manage sign-in" link |
| `SELF_CONTAINER` / `RUNNER_IMAGE` | `auth-console-app` / — | How the runner image is found |
| `LISTEN_ADDR` | `:8080` | |
| `AUTH_CONSOLE_ENV`, `DEV_IDENTITY` | `production`, — | `DEV_IDENTITY=<user>:<group,group>` skips auth, **only** when `AUTH_CONSOLE_ENV=development` and no secret is set |

The reference deployments are the `auth-console` / `auth-console-app` services of
`stacks/auth/docker-compose.yml` in `mesh-router-template-root` and in `template-root`
(`root/template/stacks/auth/`). Each template's `ensure-auth-stack.sh` mints
`AUTH_CONSOLE_ASSERTION_SECRET` before deploying the stack.

## Development

No local Go or Node is needed — build and test in containers (bind-mount the **host** path):

```bash
# Go: vet + tests
docker run --rm -v "$PWD":/src -w /src golang:1.25 sh -c 'go vet ./... && go test ./...'

# UI: type-check + build into internal/ui/dist (embedded by go build)
docker run --rm -v "$PWD":/src -w /src/web node:22 sh -c 'npm install && npm run check && npm run build'

# Image
docker build -t ghcr.io/yundera/auth-console:dev --build-arg BUILD_VERSION=dev .

# Run without a gate or a real host root
docker run --rm -p 18080:8080 \
  -e DEV_IDENTITY=dev:admins -e AUTH_CONSOLE_ENV=development -e HOST_ROOT=/nonexistent/root \
  ghcr.io/yundera/auth-console:dev
```

`vite build` overwrites the tracked placeholder `internal/ui/dist/index.html`; restore it
before committing (the Dockerfile builds the UI itself). With the Docker socket mounted
and `RUNNER_IMAGE` set, `/api/access` runs its read-only report against whatever host the
engine runs on — keep `HOST_ROOT` pointing at a nonexistent path so the account verbs
fail harmlessly.

## Release

GitHub Actions publishes `ghcr.io/yundera/auth-console` (amd64 + arm64) on pushes to
`main` and on `v*` tags. Bump by tagging (`v1.0.0` → `:1.0.0`), then move the pin in both
templates' `stacks/auth/docker-compose.yml`. **Publish the tag before moving a pin** — a
missing tag makes every self-check spend minutes in the pull backoff.
