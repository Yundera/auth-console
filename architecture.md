# auth-console — architecture

## 1. Why this service exists

Account and Access used to live in `settings-center-app`, the Next.js admin app that
ships only in the Yundera template (`admin-${DOMAIN}`), and reached the host over SSH.
That had three problems:

1. **FOSS / NSL.sh boxes had no identity UI.** The mesh template does not ship
   settings-center-app, and mesh-console covers Overview / Update / Domain only. Adding a
   user or resetting a password meant `sudo authelia-user-manager.sh` over SSH.
2. **The panel did not ship with the state it edits.** Dex and Authelia are the `auth`
   stack; the panel that administered them lived in another app. `template-root/doc/
   stack-split.md` states the rule applied here: *a panel ships with the container whose
   state it edits*. auth-console is the `accounts` app of that document.
3. **Two surfaces diverged.** One console that both templates deploy removes the second
   copy of the account UI.

## 2. What is in the stack

The `auth` compose project, deployed by each template's `ensure-auth-stack.sh` to
`/DATA/AppData/auth` (the data itself still lives under the platform root, where it was
before the stack split).

| Service (container_name) | Image | Networks | Public host | Role |
|---|---|---|---|---|
| `dex` | `ghcr.io/dexidp/dex@sha256:…` (master, pinned by digest for RP-initiated and back-channel logout) | `pcs`, internal gRPC net (alias `dex-grpc`) | `auth-${DOMAIN}` | OIDC broker for every gate on the box |
| `authelia` | `authelia/authelia:4.39.x` (never lowered) | `pcs` | `local-auth-${DOMAIN}` | Local credential store, password reset by mail, regulation, TOTP |
| `auth-registrar` | `ghcr.io/yundera/mesh-auth` | `pcs`, internal gRPC net | — (`:9092`) | Creates each gate's Dex client over gRPC — the stack's public API to the box |
| `auth-console` | `ghcr.io/yundera/appshield` | `pcs` | `auth-console-${DOMAIN}` | The gate: OIDC login, session cookie, signs `X-AppShield-Assertion`, revocation API |
| `auth-console-app` | `ghcr.io/yundera/auth-console` | `pcs` | — (`expose: 8080` only) | UI + API. Docker socket, platform root read-only |
| `auth-console-runner` | same image as the app | host namespaces | — | Not a compose service: created per host action, outside any project |

The internal gRPC network (`dex-internal` on both templates; Yundera called it `yundera-auth` until 2026-10-01) holds only
Dex's unauthenticated client API and the registrar; it must never be reachable from `pcs`.

## 3. Where it runs

One image, two templates; only paths and optional features differ.

| | Yundera PCS (`template-root`) | FOSS / NSL.sh (`mesh-router-template-root`) |
|---|---|---|
| `HOST_ROOT` | `/DATA/AppData/yundera` | `/DATA/AppData/mesh` |
| `HOST_SCRIPTS` | `$HOST_ROOT/template/scripts` | `$HOST_ROOT/scripts` (the live copy) |
| Platform `.env` | unified `.env` built from `.pcs.env` + `.pcs.secret.env` + `.ynd.user.env` | single `.env` |
| Secret minted by | `ensure_secret` (`library/secrets.sh`) in `ensure-auth-stack.sh` | `set_env_value` in `ensure-auth-stack.sh` |
| Gate user | `65534` + chowned gate-data; `extra_hosts auth-${DOMAIN}:host-gateway`, `SSL_CERT_DIR=/ca` (the hairpin fix every PCS gate carries) | `0:0` (as the maison and mesh-console gates) |
| Onboarding status | yes (`tools/onboarding.sh`) | no — claim with `install.sh --claim-*` or SSH |
| Support access | yes (`OPERATOR_API`, `feature-support-key.sh`) | no |
| Access page | yes | yes |

The console never branches on "am I on Yundera": `GET /api/capabilities` reports which
host scripts exist (through the read-only mount) and whether `OPERATOR_API` is set.

## 4. Request flow

1. The browser hits `auth-console-${DOMAIN}`. Without a session the gate registers with
   auth-registrar (client id = its container name) and redirects to Dex, which shows the
   connector chooser (Local Account = Authelia; Yundera Login on Yundera boxes).
2. The gate keeps a 30-day session and forwards each request to `auth-console-app` with a
   fresh 60 s HS256 assertion (`iss appshield`, `aud auth-console`) carrying `user`,
   `email`, `name`, `groups`, `method`.
3. The app verifies it (`internal/auth`), refuses machine methods, derives admin from the
   `admins`/`admin` group, and serves the route or answers 401 / 403.
4. A host action becomes one runner container: fixed argv, positional arguments, JSON (or
   fixed markers) on stdout, logs on stderr, exit code checked. Runs are queued
   in-process; a runner left by a previous app container is waited for, then reported
   busy (409).
5. Deleting an account or resetting its password is followed by session revocation on
   the gate (§7.3).

## 5. Identity and authorization

- **The assertion is the only identity** (ported from mesh-console, itself from
  settings-center-app): HS256 pinned, issuer and audience checked, 5 s leeway, fail-closed
  without a secret.
- **Two tiers.** `/api/me`, `/api/capabilities`, `/api/onboarding` need a person;
  everything else also needs admin. The gate enforces no group — like the admin gate,
  unlike mesh-console — because a non-admin must reach their own Account page.
- **CSRF.** Every non-GET request needs `X-Auth-Console: 1`.
- **UI hiding is cosmetic.** The Access tab is hidden for non-admins; the route check is
  the enforcement.

## 6. Naming constraints (load-bearing)

- auth-registrar derives a gate's `client_id` from a PTR lookup of the calling
  container's name and only issues redirect URIs of the form `<client_id>-<suffix>`. So
  the gate owns the public name (`auth-console`) and the backend takes `-app`. The gate's
  `APP_NAME` is the assertion audience and must equal `IDENTITY_ASSERTION_AUDIENCE`.
- It cannot be `auth` or `local-auth`: Dex owns `auth-${DOMAIN}`, Authelia
  `local-auth-${DOMAIN}`.
- `dex`, `authelia`, `auth-registrar` keep their container names: every gate on the box
  dials `http://auth-registrar:9092`, and Authelia's one client redirects to
  `https://auth-${DOMAIN}/callback`.

## 7. Host actions and state ownership

### 7.1 The runner

A privileged sibling container (`--privileged --pid=host`, `NetworkMode: none`) running
`nsenter -t 1 -m -u -i -n -p -- <argv>`, created from the app's own image. Not SSH: a FOSS
box has no admin user, key or sudoers set up for us, and one mechanism serves both
templates. The Docker socket already makes the app root-equivalent, so the runner adds no
power — only the host's view. Everything that keeps this acceptable is in
`internal/hostverb`: no generic command, no shell interpolation of input, validated
arguments, table tests per verb.

### 7.2 What the console writes

| State | Owner | How it changes |
|---|---|---|
| `auth/users_database.yml` | Authelia (this stack) | only `authelia-user-manager.sh` (`list` / `add` / `delete` / `set-password` / `set-email`) |
| Dex config, `connectors.d/` | Dex (this stack) | never — `ensure-dex.sh` renders it |
| `LOCAL_ADMIN_USER` | this stack | never — written by `claim`, read (via `list`'s `protected` flag, or the `.env`) |
| Onboarding marker | Yundera platform | never — `onboarding.sh status` is read-only here |
| `~<user>/.ssh/authorized_keys` | the host | fixed add / remove scripts (§7.4) |
| `ENSURE_SUPPORT_KEY` | Yundera platform | only `feature-support-key.sh` |
| Gate sessions | this gate | `POST /nhl-auth/sessions/revoke` |

### 7.3 Session revocation

The app signs an HS256 control token (`iss appshield-backend`, `aud appshield-control`,
60 s) with the shared secret and POSTs `{user, except?}` to its gate. `except` spares the
operator's own `appshield_session` when they reset their own password.

**Accepted v1 gap:** only this gate is reached. The same user keeps sessions on `maison`,
`mesh-console`, `terminal`, `admin` and store-app gates until they expire (30 days) or the
user signs out, and Dex's own 30-day SSO session can mint new gate sessions. Every box has
one account today; this must be closed in AppShield (e.g. gates polling a revocation feed
this stack publishes) **before multi-account ships**. The UI says so after a delete or
reset.

### 7.4 Access is host state

Access edits Linux `authorized_keys` for any host account — host-root state, the one
place the console breaks "only write state you own". It lives here because it answers the
same question as Account: who can reach this box. Safeguards:

- one validated key per call (no newline, known type, base64 body — so no `command=`
  options can be smuggled in);
- refuse a symlinked `~/.ssh` or `authorized_keys` (root would write through a link the
  user planted);
- terminate a last line that lacks a newline before appending;
- never remove the Yundera admin app's `local-admin-access` key on the dashboard account
  (checked on the host, not just in the UI) — settings-center-app still reaches the host
  with it;
- warn before removing the last `user-` key, and before disabling support access with no
  `user-` key present.

## 8. Blast radius

This stack **is login** for the whole box. The console must stay optional to it: nothing
in Dex, Authelia or the registrar depends on `auth-console` / `auth-console-app`, so a
crashed console costs only the console. Things that have broken login before and still
apply: an empty or password-less Authelia user DB, a directory where Dex expects a
bind-mounted file, an unreachable connector issuer, an Authelia image older than its
database, and restarting Authelia without a readiness wait before Dex probes it. The
break-glass path for a locked-out owner stays SSH plus `authelia-user-manager.sh`, or the
Yundera support key.

## 9. Relationship to other services

- **settings-center-app.** The Account and Access panels and the `/api/admin/users-*` and
  `access-*` routes are gone; `#/access?…` and `#/account` hashes are forwarded to the
  console, so pcs-orchestrator's support deeplink keeps working. Onboarding stays there:
  the wizard (it runs before any local account exists, through Yundera Login) and
  "Re-run onboarding" on System Information, which unclaims the box — the console only
  shows the status.
- **mesh-console.** Unchanged, still behind `OIDC_REQUIRED_GROUPS=admins`.
- **Maison.** The `auth` stack's tile (`x-compose-app`, `view: system`) opens the console.
- **pcs-orchestrator (Yundera only).** Read: `GET ${OPERATOR_API}/support/ssh-key`.
