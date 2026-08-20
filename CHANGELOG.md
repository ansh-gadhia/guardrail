# Changelog

All notable changes to GuardRail are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Versioning policy: from **1.0.0**, standard Semantic Versioning applies — MAJOR
for incompatible API changes, MINOR for backward-compatible features, PATCH for
fixes. The single source of truth is the top-level `VERSION` file; it is injected
into the binary at build time (`-ldflags -X main.version`) and surfaced at
`GET /api/v1/version`, `GET /healthz`, and in the web UI footer.

## [Unreleased]
### Security
- **The build floor is now a patch, not a minor.** `go.mod` said `go 1.26`, which
  any 1.26.x satisfies, so a build host carrying an older patch produced a
  vulnerable binary without complaint — and one was deployed that way. go1.26.5
  and earlier carry six standard-library advisories this code reaches, through
  `net/url`, `crypto/tls`, `net/http`, `encoding/xml`, `encoding/asn1` and the
  vendored `x/net/idna`. The directive now reads `go 1.26.6`.

  The patch has to sit on the `go` line specifically. A `toolchain` directive
  does not work here: `GOTOOLCHAIN=local`, which is what the golang Docker images
  set, ignores it — a 1.26.5 base image built clean while the file claimed a
  1.26.6 floor. Verified both ways round: 1.26.5 now stops with `go.mod requires
  go >= 1.26.6`, and the shipped binary reports go1.26.6.

  CI resolved 1.26.5 for the same class of reason — `setup-go` accepts the
  runner's preinstalled Go when the spec is a bare minor, and never looks for a
  newer patch. All three jobs now set `check-latest: true`.

- Dependency bumps for advisories that were present but not reached:
  `github.com/Azure/go-ntlmssp` to v0.1.1 (GO-2026-5543, NTLM challenge panic,
  pulled in by go-ldap) and `golang.org/x/net` to v0.56.0 (GO-2026-5942, SVCB/HTTPS
  record parse panic). `golang.org/x/crypto/openpgp` (GO-2026-5932) has no fixed
  version and is not imported; it stays reported and unactioned.

### Added
- **Approvals.** A device can require a decision before anybody connects to it.
  Rank comes from roles (`roles.approval_level`, seeded Super Admin 100 →
  Organization Admin 50 → Operator 10), and **an approver must outrank the
  requester strictly** — which is also what makes self-approval and
  peer-approval impossible without a separate rule. An approver gets *allow
  once*, *allow all time* and *deny*, and may shorten the window the requester
  asked for; the granted window then governs the session rather than the org
  default. Allow-all-time writes a **standing grant** with its own list and
  revoke path, because access that only accumulates and can never be enumerated
  is how a privileged-access deployment rots — and revoking one ends any session
  it is holding open. Optional **two-person rule** per device, counting distinct
  people in the database. Unanswered requests escalate one rank after 30 minutes
  and expire after another 30; an approved-but-unused request expires too.
  **Emergency access** connects immediately, notifies every approver, and lands
  in a review queue for after-the-fact sign-off — without a deliberate door,
  people route around approvals by sharing the break-glass credential. New
  permissions `approval:read`, `approval:decide` and `approval:bypass`; bypass
  exempts the holder's own connects and says nothing about deciding other
  people's. New console page **Approvals**, and a device-side **Access policy**
  panel. Migrations `0027`, `0028`.

  This restores a workflow that `0008_drop_approvals` removed in favour of
  role-based device entitlement; the README's M6 claim had been false since then.

- **Per-user accounts.** A device can inject each person's own named account on
  the target (`jsmith-admin`) instead of one shared login, so the device's own
  logs record who was actually there. Accounts bind to a device or — the part
  that makes it survive scale — to an **asset group**, covering everything in its
  subtree with the nearest ancestor winning. A per-user device **never falls back
  to the shared credential**: falling back would log somebody in as the shared
  admin account when they were supposed to appear under their own name, which is
  the whole thing the mode exists to prevent. CSV bulk import, an "ageing
  secrets" view driven by `credentials.rotated_at`, offboarding that retires a
  departed person's accounts, and a **whoami** endpoint that answers "which
  account will I connect as" before the click. `credential.use` audit events now
  carry the account name, so GuardRail's trail can be joined to the target's own
  logs. Migration `0026`.

- **Member role editing, a protected installation account, and admin password
  reset.** The console can now escalate or downgrade a member's roles from the
  Members list; the dialog states the approval rank before and after, warns when
  Super Admin is granted or removed, warns when the last role is unticked, and
  says that saving signs the person out. Administrators can issue a **temporary
  password** for somebody who is locked out — generated, shown once, forced to
  change at next sign-in, and revoking every existing session. The password
  avoids `0/O`, `1/l/I` and `5/S`, because a reset password gets read aloud.

  The account `seed-admin` creates cannot have its **roles changed or its
  password reset**, by anybody, including other super admins and itself: it is
  the recovery path, and a demoted or reset copy of it lets nobody back in. It
  **can** be removed — removal frees the email address, so `guardrail seed-admin`
  on the server puts it back. That is the difference: deletion is the one change
  to this account that can be undone from outside the product.
  Identified by the `is_super_admin` column, not by holding the Super Admin role,
  so console-promoted super admins stay fully manageable. Refused attempts are
  audited.

### Changed
- **Emergency access is rationed.** The break-glass button is reachable by
  anybody the approval gate applies to, on purpose — a door people can see beats
  a wall they climb by sharing the break-glass credential — but reachable and
  unlimited are different settings, and only the second one made the whole
  approval workflow advisory. Nobody had to ask for anything.

  One person may now take `GUARDRAIL_EMERGENCY_QUOTA` emergency accesses per
  `GUARDRAIL_EMERGENCY_QUOTA_WINDOW` (default **2 per 7 days**), sized so routine
  use runs out and genuine use does not. Past the limit the connect is refused
  with 429 and a sentence naming **when the next one frees up**, because "denied"
  during the incident somebody pressed that button in does not tell them whether
  to wait or to go and wake an approver. Asking for approval is unaffected — the
  point is to push people back to it, not to lock them out. Refusals are audited
  as `approval.emergency_refused`. Set the quota to 0 to remove the limit.

  It counts accesses **taken**, not attempted: an emergency that never became a
  session — no credential bound, gateway refused — gave nobody access, and
  charging for it would spend a week's allowance on a misconfiguration and shut
  the door during the incident it exists for. The console says the allowance
  exists *before* the click, since finding out mid-incident that you spent your
  last one a fortnight ago is being told too late to act on it.

- **A session in continuous use is no longer cut off after an hour.** Two limits
  govern session length and they had been conflated. The per-device idle timeout
  (`idle_timeout_minutes`, default 60) is measured from the last keystroke or
  proxied request and is what ends an ordinary session — every gateway stamps
  activity, so somebody working is never cut off mid-task. The access window was
  a flat hour that ignored activity entirely, and the gateway holds that deadline
  too and refuses to proxy past it, so it was not a formality: an operator with
  work in progress lost the session at sixty minutes.

  An ordinary session now runs to a **ceiling** instead — `GUARDRAIL_MAX_SESSION_WINDOW`,
  default 12h — with the idle timeout as the operative control. Bounded rather
  than unlimited on purpose: an unbounded privileged session is what a
  privileged-access platform should not hand out, and a forgotten tab held open
  by a background poll would otherwise live forever.

  **Approved windows are unchanged and stay absolute.** An approver who grants
  thirty minutes grants thirty minutes; activity does not extend it, or the
  window would not be one. `GUARDRAIL_APPROVAL_WINDOW` (default 1h) is only the
  fallback for an approved request that named no duration.

  The live-session index TTL now follows the session's actual window rather than
  a flat hour, which had been dropping long approved sessions out of the active
  list and leaving short ones in it after they ended.

### Added
- **A device can be edited after it is registered.** The console could create a
  device and never change what it *is*: name, host/IP, port, protocol, vendor,
  type and description rendered as read-only text on the device page, so a box
  that moved to a new address — or was typed in wrong — had to be deleted and
  re-registered, taking its sessions, recordings and audit trail with it. The API
  has accepted `PATCH /devices/:id` all along; only the form was missing. It is
  behind `device:write`, the same permission that registers a device.

  Changing the protocol warns first, because it can invalidate things settled
  against the old one — a credential's injection method, isolated delivery on a
  device that is no longer web. The server still refuses combinations it cannot
  honour; the warning just means you find out before pressing Save.

  Recording policy is deliberately not in this form. It stays owner-or-super-admin
  and keeps its own control.

### Changed
- **Bulk import of per-user accounts no longer asks for UUIDs.** It took
  hand-written CSV whose every row carried a raw `device_id` or `group_id` —
  identifiers nobody has memorized and which this console is the only place to
  look up, so using the feature meant copying UUIDs out of one screen into a text
  box on another and counting commas to find the row a failure referred to. The
  target and the injection method are the same for every row of a real import, so
  they are now chosen once from a picker that lists groups and devices **by
  name**, and a row carries only what differs per person: who, the account name
  on the device, the secret.

  Choosing a device also filters the injection methods to the ones its protocol
  can actually accept, so the mismatch the server rejects (`"basic" cannot
  authenticate a ssh device`) can no longer be built in the first place.

  Pasting a list still works — it is what comes out of whatever system already
  knows which account belongs to whom — but it is now `email,username,secret`
  with no header. An address matching no GuardRail user is named in the console
  instead of being sent and rejected, so that line's secret never leaves the
  browser. Failures come back against the person rather than a row number, and a
  successful import clears the secrets out of the form.

  One capability is lost: a single import can no longer span several devices or
  groups, because the target is chosen once. Import once per target.

### Fixed
- **The Audit Log said access was denied when it had been approved.** Raising an
  access request was recorded as `approval.requested` with the outcome `denied`,
  so the log showed "approval.requested — denied" directly above the
  "approval.granted — success" for the same `request_id`: it contradicted itself
  about access that an approver had allowed seconds later. Nobody had refused
  anything at that point, and the row could never be corrected, because the log
  is an append-only hash chain. Asking for access is now recorded as `pending` —
  a fourth outcome added for exactly this, since the vocabulary is a closed
  `CHECK` in the schema (migration `0029`) — and the Audit Log gains a Pending
  filter. The two rows already written keep saying `denied`; rewriting them is
  what the chain exists to prevent.
- **A refused attempt to switch recording off was logged as a success.** Only a
  device's owner or a super admin may change its recording policy, and a refusal
  audits as `device.recording_denied` — through a helper that hardcoded
  `success`. Filtering the Audit Log for denials never surfaced it, and the row a
  reviewer did see read as though the change had gone through. Recording is
  evidence, so an attempt to remove it is precisely the row that has to be
  accurate. It now records `denied`.
- **Audit events that belong to no session claimed one.** The approval and denial
  paths pass a bare session to name the device, and the recorder took its id
  unconditionally, stamping every one of those events with
  `00000000-0000-0000-0000-000000000000` — a session that has never existed, in
  the column whose only purpose is joining an event back to a session.
  `approval.reviewed`, which carries no device either, additionally named
  device `00000000-…`. Both are left NULL now.
- **Rotating a per-user account silently changed how its secret was injected.**
  The Rotate dialog sends a username and a secret; it sent no injection method,
  and the write path resolved an absent one to the protocol's default. So an
  account bound with an SSH **private key** came back as `ssh-password` with the
  PEM still in the vault — the rotation reported success and the next connect was
  the first anybody heard of it. An omitted method now keeps the stored one
  (empty never means "clear it" — `none` does), matching what `Rotate` on a
  plain credential already did. The group dialog had the same bug from the other
  end: its method picker was hardcoded to `ssh-password` regardless of what the
  account was bound with, so opening it and pressing Save rewrote the method.
  Both dialogs now show the bound method, and the device one offers only the
  methods its protocol accepts.
- **The asset-group picker was an empty dropdown with no explanation.** With no
  groups defined it rendered "Choose an asset group…" and nothing else, which
  looks identical to a list that failed to load or one you lack `group:read` to
  see — three different problems, one blank control, no way to tell which you
  had. Each case now says what it is, and the empty one points at where groups
  are actually created (on a device).
- The group-account dialog's injection list was written out by hand and was
  missing the Authorization-header method, so a group of API-token devices could
  not be bound from it. Both surfaces now share one list.
- **Approvals → Open access listed every one-off ever used as still in use.** A
  redeemed request keeps its `session_id` forever, and its status stays
  `approved` — a one-off is spent when it is used, not re-decided — so nothing on
  the request itself ever says the access is over. The "One-off — in use" panel
  filtered on the pointer, and therefore claimed live access for sessions that
  had ended a day earlier, next to the window they were long past and an "Open
  session" link to a session with nothing left to end. A grants screen exists to
  answer "who can reach a gated device right now", and that answer has to be
  about now. Requests now carry `session_active`, resolved from the session
  itself, and only genuinely open sessions are listed; a spent one-off appears
  under History, where it belongs. The window is also labelled "Allowed 1 h"
  rather than a bare "1 h", which read as a countdown.
- **The Access Log told people without permission that everything was fine.** The
  sign-in history query is disabled without `log:read`, and a disabled query in
  React Query is pending-but-not-fetching — `isLoading` false, `data` undefined —
  so it fell through to the empty state and rendered "No failed sign-in attempts
  — all clear." to somebody who simply was not allowed to look. Meanwhile the
  stat above it is served by `/dashboard/summary`, which requires no permission
  at all, so the same screen could read **"Failed · 24h: 2"** and **"all clear"**
  simultaneously. It now says the permission is missing. On a security console,
  asserting safety on the strength of a failed authorization check is the worst
  available answer.
- The same panel's failed-login stat defaulted to **0** when the summary request
  failed, which is a security console reporting all-clear because it could not
  ask. It shows "—" when the number is unknown.
- The failed-login count is cross-tenant for a super admin and org-scoped for
  everybody else, so two people reading the same label saw different numbers. The
  super admin's is now labelled **"Failed · 24h · all orgs"**.
- **Connecting to an approval-gated device returned 500 "unexpected error".**
  Every first click, for anybody not exempt. The console connects with an empty
  body to find out whether the gate applies — it cannot know from the device row,
  because bypass, device ownership, a standing grant and an approval already in
  hand are all decided server-side — and that probe reached the code that raises
  a request, which refused it for having no reason. The refusal was
  `access.ErrInvalid`, which nothing mapped, so it fell through to a 500.

  The gate now answers the probe with `202 {"status":"approval_required"}` and
  the console opens the reason dialog. Pressing Connect again while a request is
  in flight returns that request instead of asking twice, and the dialog opens on
  its waiting view rather than a blank form. `access.ErrInvalid` maps to 400.
  Reasons are trimmed server-side, so whitespace is not a reason.
- **The approval hierarchy was inert.** The query that loads a user's roles never
  selected `roles.approval_level`, so every principal and every JWT carried rank
  0 — and because an approver must outrank the requester strictly, `0 > 0` meant
  **no non-super-admin could approve anything**. Earlier tests missed it because
  they passed levels in at the repository layer, and every end-to-end approval
  was performed by a super admin, who bypasses rank.
- The device credential pre-flight asked a device-wide question while resolution
  asks a per-person one. On a per-user device that let a connect pass on somebody
  else's account, create the session, emit the audit event, and only fail when
  the gateway asked for the secret — mid-connect, with a session row already
  written. Both now branch on `credential_mode` in the same query.
- `device_credentials.is_default` is dropped. With an owner column present it
  could no longer be answered ("default for whom?"), and a flag that cannot be
  answered is a second, contradictory source of truth for resolution.


## [1.0.0] - 2026-07-16 — First stable release
### Added
- **Terminal & desktop protocols.** Beyond web UIs, GuardRail now brokers `ssh`
  and `telnet` terminals (server-side gateway; SSH keeps a replayable transcript)
  and `rdp` / `vnc` desktops through an Apache **guacd 1.5.5** sidecar, rendered to
  a canvas in the browser. Telnet was added end to end — protocol vocabulary in
  both bounded contexts, the vault injection rule, the console picker, the guacd
  client (with a Cisco `Username:` login-prompt regex), and schema (`0021`). All
  behind the `desktop` Compose profile, off by default.
- **In-console recording playback.** RDP/VNC/telnet sessions are recorded by guacd
  as Guacamole protocol dumps and replayed in the **Recordings** page, alongside
  the existing video (isolated web) and SSH transcript players. The desktop viewer
  gains a full-screen control, a clipboard **Paste** affordance (Ctrl+Shift+V for
  terminals, Ctrl+V for desktops), an attribution watermark, and native-resolution
  sizing. Recording deletion (`recording:delete`) added.
- **Setup guide + as-built architecture.** New top-level [`SETUP.md`](SETUP.md)
  for a fresh server: prerequisites, an architecture diagram, the default port
  map, first sign-in, enabling desktop protocols, and troubleshooting.
  `docs/ARCHITECTURE.md` updated to the shipped in-process-gateway topology.
- **Access Log — live console sign-in visibility.** New `GET /api/v1/auth/sessions`
  lists active login sessions (one row per refresh-token *family*, so token
  rotation shows as a single logical sign-in): user, source IP, parsed client,
  original sign-in time, last activity, and expiry. An operator with `user:read`
  sees their whole tenant (super admin sees everything); everyone else sees only
  their own. Each row can be force-signed-out via
  `POST /api/v1/auth/sessions/:id/revoke` (own session always; another user's
  requires `user:write`, tenant-scoped). The caller's *current* session is flagged
  by matching the refresh cookie. New **Access Log** page (Governance) pairs the
  live-sessions table with a recent sign-in history sourced from the audit feed.
  All timestamps cross the wire as UTC RFC3339 and render in the viewer's local
  timezone — TOTP and session logic never touch a local clock. No schema change.
- **Authenticator QR + hardened TOTP enrollment.** The Two-factor setup now renders
  a scannable QR of the `otpauth://` URI (drawn client-side, so the secret never
  leaves the browser) alongside the manual setup key. Enrollment confirmation now
  requires **two consecutive codes** (`POST /api/v1/mfa/totp/confirm` takes
  `code` + `next_code`) — proving the authenticator's clock tracks the server
  across a period rollover, so a time-drifted device is caught at setup instead of
  locking the user out at next sign-in. Sign-in still takes a single code.
- **Access Log now surfaces failed sign-ins.** The sign-in history panel reads the
  full `auth.login` audit stream (not just successes) and adds an All / Failed
  filter; each failed row shows the attempted identity, a human-readable reason
  (bad password, unknown user, locked out, MFA failed, …) mapped from the audit
  `detail`, the source IP, and when it happened.
- **Audit log — full activity coverage + event detail drawer.** The audit read
  model now returns the event `detail` map and `user_agent`, and clicking any row
  opens a detail drawer showing exactly what happened: when (local **and** UTC),
  the actor, the action, the target, the source IP, the client, every structured
  detail field, and a tamper-evidence note (the log is hash-chained / append-only).
  Several coverage gaps were closed so every mutating action is recorded — asset-
  group create and membership changes (`group.create`, `group.add_member`),
  approval denials (`approval.deny`), and notification-channel create/delete
  (`channel.create`, `channel.delete`) join the device / credential / session /
  user events already audited. (Device registration `device.create` and connect
  `session.start` were already audited — they were just not fully shown before.)
- **Session identity watermark.** The in-app brokered-session view tiles the
  operator's identity (`email · short-session-id`) faintly across the proxied
  page, so any screen capture of a privileged session carries who was in it.
  Deliberately low-contrast — present on every frame without obscuring the target.
- **Recordings tab + per-session activity timeline.** A new **Recordings** page
  (Access) lists every brokered session — user, device, protocol, status, start,
  duration, client IP — and a detail drawer shows the full lifecycle (start / end,
  end reason, gateway, client) plus an **activity timeline** of the pages reached
  through the proxy (`method path`, captured server-side) for both live and ended
  sessions.
- **Auto-terminate on tab close.** Closing the live-session tab now terminates the
  session server-side immediately via a `pagehide` keepalive beacon, instead of
  leaving it to the overdue-session reaper — no orphaned privileged sessions.
- **Primary super admin is bootstrapped from the environment.** `GUARDRAIL_ADMIN_EMAIL`
  / `GUARDRAIL_ADMIN_PASSWORD` (+ `GUARDRAIL_ADMIN_USERNAME` / `GUARDRAIL_ADMIN_ORG`)
  are seeded idempotently on first boot — set/change them in `.env` before the
  first start. The process fails closed if the password is set but < 12 chars.
  Manual `seed-admin` still works when the vars are empty.
- **Self-service change password** — `POST /api/v1/auth/change-password` verifies
  the current password, enforces the policy, revokes all other refresh sessions,
  and re-issues the caller's session. Surfaced in the console as a dedicated
  **Account → Password** tab with a live strength meter.
- **Redesigned web console** — a token-based (CSS-variable) design system: card /
  tile / box layouts replace the old tables across Devices, Credentials, Sessions,
  Approvals, Users & Roles and the Dashboard; a `PageHero` banner, KPI `Stat`
  tiles, `Panel`/`Badge`/`Tabs` primitives, an inline-SVG icon set, a grouped
  sidebar with an active rail and ambient background, and skeleton loaders. RBAC
  still gates nav and actions (permission-filtered sidebar, disabled/guarded
  buttons).

### Security
- **Connect is now fail-closed when a device has no bound credential.** Previously
  the access broker/gateway swallowed `ErrNoCredential` and proxied the device's
  own login page with no server-side injection — leaking the target and defeating
  the "credentials never reach the user" guarantee. The broker now refuses before
  creating any session or approval (HTTP `412 No Credential`), and the gateway
  fails closed as defence-in-depth. A new per-device **`allow_unmanaged`**
  break-glass flag (default `false`) is the explicit, audited opt-out for
  deliberate no-auth / credential-less targets. Migration `0007`.
### Added
- Device list/detail responses now include **`has_credential`** and
  **`allow_unmanaged`**; the console surfaces per-device credential status
  (`bound` / `none` / `break-glass`), stat tiles (Credentialed / Needs credential
  / Break-glass), disables **Connect** for credential-less managed devices, and
  exposes the break-glass toggle in the Add-device form.
### Fixed
- Restored two zero-filled source files (`frontend/index.html`,
  `frontend/tsconfig.json`) so the SPA type-checks and builds.
- **Desktop recording playback.** `guacamole-common-js` 1.5.0 (the newest release)
  cannot play a recording from a Blob — its `SessionRecording(Blob)` constructor
  parses `undefined` and throws. The console now feeds the recording through the
  library's working tunnel path via a small replay tunnel, so RDP/VNC/telnet
  recordings play back. Recording fetch errors are now reported precisely
  (HTTP status vs empty vs unparsable) instead of a blanket message.
- **Desktop recording capture.** The guacd→API recording handover is now robust:
  guacd (uid 1000) writes the recording group-readable and the API joins guacd's
  group (`group_add`), so recordings are collected regardless of the API's uid.
  Empty/failed recordings are logged with the directory's actual ownership.
- **RDP correctness.** Mouse clicks now account for display scaling (were offset on
  a scaled desktop); the desktop is requested at the browser's size instead of
  running at a fixed geometry; break-glass negotiates security instead of pinning a
  mode Windows refuses; and a credential with no username is refused for RDP/telnet
  rather than silently logging in as the wrong Windows user.
- **Console.** Telnet now offers the correct (password-only) credential method; the
  Devices "managed" coverage meter no longer double-counts and exceeds 100%.

## [0.9.0] - 2026-07-14 — M7: Web Console (React SPA)
### Added
- **GuardRail web console** — React 18 + TypeScript + Vite + Tailwind SPA under
  `frontend/`, served in production by nginx (multi-stage Docker build) and wired
  into `docker-compose` behind Traefik.
- Screens: **Login** (local + TOTP MFA challenge + LDAP tab + OIDC SSO button,
  driven by `/auth/providers`), **Dashboard** (counts, top devices, recent
  activity), **Devices** (list + approval-aware Connect), **Sessions** (live
  auto-refreshing monitor + terminate), **Approvals** (approve/deny),
  **Audit Log** (filter + CSV export), **Security** (self-service TOTP
  enrollment, recovery codes, disable), and **global search**.
- Data layer: React Query (caching/polling/invalidation), Zustand auth store.
  The **access token is held only in memory**; refresh uses the HttpOnly cookie
  with a single silent-refresh-on-401 interceptor. RBAC-aware UI (buttons gate on
  the principal's permissions).
- The app **version is displayed in the sidebar footer**, sourced live from
  `GET /api/v1/version` (single source of truth: the `VERSION` file).
### Changed
- CI now applies **all** migrations (`migrations/*.up.sql`) before integration
  tests, not just the first two.

## [0.8.0] - 2026-07-14 — M3: MFA & Federation
### Added
- **TOTP multi-factor authentication** (RFC 6238): self-service enrollment
  (`POST /mfa/totp/enroll` → secret + otpauth QR URI), confirmation
  (`POST /mfa/totp/confirm`), status, disable, and recovery-code regeneration.
  Enrollment mints 10 single-use recovery codes. TOTP secrets are stored
  envelope-encrypted under the vault KEK.
- **MFA-gated login**: after a correct password, an enrolled user receives a
  short-lived, HMAC-signed challenge; `POST /auth/mfa/verify` completes sign-in
  with a TOTP or a single-use recovery code. Brute-force throttled.
- **OIDC federation** (Authorization Code + PKCE, hand-rolled, no heavyweight
  deps): discovery, JWKS-based RS256 ID-token verification, issuer/audience/
  nonce checks. `GET /auth/oidc/start` → signed transaction cookie + IdP
  redirect; `GET /auth/oidc/callback` → JIT user provisioning + tokens.
- **LDAP/AD federation**: search-then-bind authentication with attribute
  mapping (`POST /auth/ldap/login`); empty-password (unauthenticated-bind) guard.
- `GET /auth/providers` advertises enabled login methods to the SPA.
- **SAML** service-provider stub with the config + interface shape defined for a
  future binding (documented roadmap).
### Security
- Federated sign-ins are audited (`auth.oidc` / `auth.ldap` / `user.provision`);
  new federated users start with no roles until an admin grants access.

## [0.7.0] - 2026-07-14 — M8: Dashboard, Search, Audit Log & Reports
### Added
- **Dashboard summary** (`GET /dashboard/summary`): tenant-scoped aggregates —
  device / active-session / user counts, failed logins in the last 24h, top
  devices by session volume, and a recent-activity feed from the audit log.
- **Global search** (`GET /search?q=`): case-insensitive search across users,
  devices, and sessions in a single call.
- **Audit log read API** (`GET /audit`): filter by action, actor, result, and
  time window; newest-first, bounded page size; gated by `log:read`.
- **Reports** (`POST /reports`): CSV export of the audit log (`type: audit`) or
  the access-session history (`type: access`), with an optional time window;
  gated by `report:read`.
### Notes
- All read-model queries run inside the tenant-scoped RLS transaction, so a
  super admin sees cross-tenant results while an org user is confined to its org.

## [0.6.0] - 2026-07-14 — M6: Approvals, Monitoring & Notifications
### Added
- Optional per-device **approval workflow**: connect to a gated device creates a
  pending session + approval request; an approver approves/denies; the requester
  then starts the approved session within its window. Approvals auto-expire.
- Live session monitoring (`GET /sessions/active`) and force-terminate, backed by
  a Redis live-session registry with cross-node terminate signalling.
- **Notification channels** (webhook, Slack, email) with a transactional outbox
  and a background dispatcher (retries, then dead-letter after 5 attempts).
  Broker events (`approval.requested`, `approval.decided`, ...) fan out to
  subscribed channels.
- Background workers: notification dispatcher + overdue-session reaper.
### Changed
- `POST /devices/:id/connect` now returns `202 pending_approval` for gated
  devices; added `POST /sessions/:id/start`, `GET /approvals`,
  `POST /approvals/:id/approve|deny`, and notification-channel CRUD.

## [0.5.0] - 2026-07-14 — M5: Access Broker, Secure Proxy & Recording
### Added
- **Secure web proxy gateway**: a credential-injecting reverse proxy. On connect,
  the broker establishes a session, the gateway resolves the device credential
  just-in-time (held in memory only) and injects it server-side (HTTP Basic or
  header) so it is **never exposed to the user's browser**.
- Access broker: authorize → time-box → establish → record → terminate, with a
  pluggable `Gateway` contract so SSH/RDP/VNC/etc. add without core changes.
- Session lifecycle: `POST /devices/:id/connect`, list/active/get/terminate,
  per-session HttpOnly proxy cookie binding the browser to the session.
- Session recording metadata + a playback event timeline (`url_change`, ...).
- Live-session registry and cross-node terminate signalling in Redis.
- SSRF guard blocking cloud-metadata/link-local targets; overdue-session reaper.
### Security
- Credentials resolved one-shot and audited as `credential.use`; full
  `session.start`/`session.end` audit; RLS on all session/recording tables.

## [0.4.0] - 2026-07-14 — M4: Assets & Credential Vault
### Added
- Device registry: full CRUD (name, vendor, type, host, port, scheme, TLS
  verification, custom headers, tags, status) with per-tenant uniqueness.
- Credential vault with **envelope encryption** (AES-256-GCM DEK per credential,
  wrapped by a KEK from a pluggable `KeyProvider`; env provider ships now).
  Secrets are **write-only** over the API and never returned in plaintext.
- KEK rotation (`Rewrap`) that re-wraps DEKs without touching ciphertext.
- Device⇄credential binding and asset groups (folders, nesting, membership).
- `GET /api/v1/version` endpoint and a `VERSION` file as the single source of truth.
### Security
- RLS policies and least-privilege grants extended to all asset/vault tables.

## [0.3.0] - 2026-07-14 — M2: IAM (AuthN, RBAC, Tenancy, Audit)
### Added
- Local authentication with Argon2id (rehash-on-login, decoy verify against user
  enumeration); brute-force throttle (Redis) + account lockout.
- JWT access tokens and opaque refresh tokens with **rotation + reuse detection**
  (family revocation).
- RBAC middleware over a granular permission catalogue; deny-by-default routes.
- Two-layer multi-tenant isolation: application `TenantScope` + PostgreSQL RLS
  enforced via a non-superuser application role.
- Tamper-evident, hash-chained audit log (append-only; no UPDATE/DELETE grant).
- Organization/user CRUD, role assignment, `seed-admin` bootstrap command.
### Tests
- Unit (Argon2, JWT, login/lockout/refresh-reuse, RBAC) + live-DB integration.

## [0.2.0] - 2026-07-13 — M1: Foundation & Platform
### Added
- 12-factor config with fail-closed validation, structured JSON logging (zap).
- Gin HTTP server with security-header/request-id/recovery/metrics middleware,
  graceful shutdown; `/healthz`, `/readyz`, `/metrics`.
- PostgreSQL (pgx) and Redis adapters; migrations (`golang-migrate`) with RLS
  scaffolding and seed data.
- Docker multi-stage build (distroless, non-root), docker-compose stack,
  Makefile, `.env.example`, golangci-lint, GitHub Actions CI.

## [0.1.0] - 2026-07-13 — M0: Design
### Added
- Architecture, data model, API specification, security design, sequence/ER
  diagrams, and milestone roadmap under `docs/`.

[Unreleased]: https://github.com/ansh-gadhia/guardrail/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/ansh-gadhia/guardrail/releases/tag/v1.0.0
[0.9.0]: https://github.com/ansh-gadhia/guardrail/releases/tag/v0.9.0
[0.8.0]: https://github.com/ansh-gadhia/guardrail/releases/tag/v0.8.0
[0.7.0]: https://github.com/ansh-gadhia/guardrail/releases/tag/v0.7.0
[0.6.0]: https://github.com/ansh-gadhia/guardrail/releases/tag/v0.6.0
[0.5.0]: https://github.com/ansh-gadhia/guardrail/releases/tag/v0.5.0
[0.4.0]: https://github.com/ansh-gadhia/guardrail/releases/tag/v0.4.0
[0.3.0]: https://github.com/ansh-gadhia/guardrail/releases/tag/v0.3.0
[0.2.0]: https://github.com/ansh-gadhia/guardrail/releases/tag/v0.2.0
[0.1.0]: https://github.com/ansh-gadhia/guardrail/releases/tag/v0.1.0
