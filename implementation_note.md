# auth-console — implementation notes

State as of 2026-09-30: service implemented, wired into both templates' `auth` stack,
Account/Access removed from settings-center-app. Nothing committed or published yet.

## Decisions

| Decision | Date | Notes |
|---|---|---|
| Name `auth-console` everywhere (gate, `-app`, runner, host, image) | 2026-09-30 | The name both stack files had reserved. `stack-split.md` calls this app `accounts`; it is the same thing |
| Ship in the existing `auth` stack | 2026-09-30 | The stack split had already moved dex / authelia / auth-registrar into their own project; the console joins it. No data moved |
| Go 1.25 + Svelte 5, ported from mesh-console | 2026-09-30 | |
| Claiming stays on the command line | 2026-09-30 | An unclaimed box has no Local Account connector (on FOSS, no connector at all), so nobody can reach the console before the owner claims. No claim flow, no unauthenticated route besides `/api/health`, no runner stdin |
| Scripts stay in the templates | 2026-09-30 | The runner calls `authelia-user-manager.sh` & co. in each template's `scripts/`; not Maison `pre_up` hooks (template-deployed stacks don't run them, and a failing hook blocks every start of the stack that is login) |
| Revocation covers this gate only | 2026-09-30 | Accepted v1 gap, see architecture.md §7.3. Fix in AppShield before multi-account |
| Password self-service stays in Authelia's portal | 2026-09-30 | The console never handles a user's own password |
| "Re-run onboarding" lives in the admin app, not the console | 2026-09-30 | Revised the same day from "terminal-only": it sits next to the wizard it replays (settings-center-app, System Information), refuses while Yundera Login is off, and revokes the other admin gate sessions. The console shows onboarding status only |
| Access ships on FOSS too | 2026-09-30 | Same guards; support access is Yundera-only |

## Code map

| Path | What |
|---|---|
| `cmd/auth-console` | main: config, server, graceful shutdown |
| `internal/auth` | assertion verification; `RequireUser` (person, any group) and `RequireAdmin` |
| `internal/config` | env settings |
| `internal/envfile` | reads the platform `.env` per request, through the read-only mount |
| `internal/dockerx` | the runner: `RunOnHost` (stdout/stderr kept apart, in-process queue, 60 s wait), `ImageOf` |
| `internal/hostverb` | every host action: user-manager verbs, `onboarding.sh status`, support status/set, access report, add/remove key; validation |
| `internal/access` | parser for the access report (port of settings-center-app's `access-info.ts`) |
| `internal/pubkey` | deep-link key fetch; SSRF check in the dialer |
| `internal/gatectl` | session revocation on the gate |
| `internal/server` | routes, handlers, SPA |
| `web/` | Svelte UI: `pages/Account.svelte`, `pages/Access.svelte`, `lib/sshKeygen.ts` (verbatim from settings-center-app) |

## API

| Route | Guard | Host action | settings-center-app predecessor |
|---|---|---|---|
| `GET /api/health` | none | — | — |
| `GET /api/me` | user | — | `GET /api/me` |
| `GET /api/capabilities` | user | — (mount) | — |
| `GET /api/onboarding` | user | `onboarding.sh status` | `GET /api/admin/onboarding-status` |
| `GET /api/users` | admin | `authelia-user-manager.sh list` | `GET /api/admin/users-list` |
| `POST /api/users` | admin | `… add` | `POST /api/admin/users-add` |
| `DELETE /api/users/{u}` | admin | `… delete` + revoke `{user}` | `POST /api/admin/users-delete` |
| `POST /api/users/{u}/reset-password` | admin | `… set-password` + revoke `{user, except}` | `POST /api/admin/users-set-password` |
| `PUT /api/users/{u}/email` | admin | `… set-email` | `POST /api/admin/users-set-email` |
| `GET /api/access` | admin | access report | `GET /api/admin/access-info` |
| `POST /api/access/keys` | admin | add-key script | `POST /api/admin/access-add-key` |
| `DELETE /api/access/keys` | admin | access report (guard) + remove-key script | `POST /api/admin/access-remove-key` |
| `GET /api/access/fetch-pubkey?url=` | admin | — | `GET /api/admin/access-fetch-pubkey` |
| `GET/PUT /api/access/support` | admin | support status / `feature-support-key.sh` | `GET/POST /api/admin/support-ensure` |

Status mapping: a script's own `ERROR: …` line → 400 with that message; any other failed
host action → 502; runner busy → 409; key scripts' exit 2 / 3 / 4 → 404 / 409 / 409.

## Fixed on the way (vs. settings-center-app)

- **Owner detection.** The owner was hard-coded as `admin`; it is whoever claimed
  (`LOCAL_ADMIN_USER`). `authelia-user-manager.sh list` now returns `protected` (both
  templates); the app falls back to `LOCAL_ADMIN_USER` from the `.env`, then `admin`, for
  a template older than that.
- **Unreachable 404 / 409 on add-key.** The TS executor threw on any non-zero exit before
  the handler could map `USER_NOT_FOUND` / `HOME_MISSING`; the runner returns the exit
  code, so they map as intended.
- **DNS rebinding in the deep-link fetch.** The TS version resolved, checked, then let
  `fetch()` resolve again; the check now runs on the dialled address. The timeout also
  covers the body, and 100.64/10 and 198.18/15 are blocked.
- **Key-file hardening.** Symlinked `~/.ssh` / `authorized_keys` refused; a missing final
  newline no longer glues the new key onto the previous one.
- **Web onboarding reset** moved to the admin app's System Information panel, now guarded (Yundera Login must be on) and revoking the other admin gate sessions — it used to revoke none.

## settings-center-app changes (same rollout)

- Deleted (1.4.8): `panels/access/`, `pages/api/admin/{users-*,access-*}.ts`,
  `backend/server/Users/AutheliaUsers.ts`, and the helpers only they used
  (`getContainerKeyFingerprint`, `trustedPubkeyHostSuffixes`).
- Deleted (after 1.4.8): the Account panel itself. "Re-run onboarding" came back as a
  System Information card (`component/RerunOnboarding.tsx`, `onboarding-reset.ts`, with
  `gateControl.ts` / `gateSessionId` / `APPSHIELD_GATE_URL` restored for its revocation).
- `App.tsx` forwards `#/access?…` to `auth-console-<domain>/access?…` and `#/account` to
  the console's Account page, so
  pcs-orchestrator's `buildSupportDeeplink` (`pcsAPI.ts`) keeps working without a change.
  Pointing the orchestrator at auth-console directly can wait until no box runs a
  template without the console.

## Rollout order

1. Commit and tag this repo (`v1.0.0`); wait for `ghcr.io/yundera/auth-console:1.0.0`.
   Both templates already pin `:1.0.0`.
2. Commit the two templates (`mesh-router-template-root`, `template-root`) and bump the
   submodule pointers. The next self-check mints `AUTH_CONSOLE_ASSERTION_SECRET`, deploys
   the two new services into the `auth` project and points the Auth tile at the console.
3. Commit settings-center-app, tag a release, **then** move its pin in
   `template-root/root/docker-compose.yml` (currently `1.4.6`). Until then boxes keep the
   old Account/Access panels next to the console, which is harmless. The
   `APPSHIELD_GATE_URL` env on `admin-app` can go with that pin bump.

## Testing

- Unit (run in `golang:1.25`): auth tiers and machine refusal, handler status mapping with
  a fake runner, verb argv and hostile-input tables, access-report parsing, revocation
  token claims, pubkey fetch (private IPs, loopback at dial time, redirects, oversize).
- Local: the image's `/api/access` against the Docker VM (read-only report), three
  concurrent requests queued through the one runner.
- Not yet on a box. Test plan (pre-authorized boxes only — never yunderalabs /
  yunderateam): **watch** (`ssh admin@85.17.246.67`, mesh) and **holyhorse**
  (`ssh admin@185.216.75.105`, Yundera). Ship the image with `docker save | gzip | ssh …
  'gunzip | sudo docker load'`, tag it `1.0.0`, and deliver the template as a `file://`
  tarball via `UPDATE_URL` / `MESH_TEMPLATE_URL` so the nightly sync does not revert it.
  Check: login at `auth-console-<domain>`; list / add / reset / revoke a user and log in
  with the one-time password; the owner cannot be revoked or re-addressed; an admin cannot
  revoke themselves; a non-admin sees Account only and gets 403 on `/api/users`; add a
  generated key, SSH in with it, remove it; the last-`user-`-key warning; support toggle
  and onboarding status (holyhorse); the orchestrator's `#/access` deep link lands on the
  console's consent card; stop `auth-console-app` and confirm Maison login still works.
