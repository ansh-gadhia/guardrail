# GuardRail — Using the Platform

This is the end-to-end operator workflow: from first sign-in to a fully audited,
credential-injected browser session — plus MFA, approvals, and reporting. Every
step works from the **web console** (http://localhost/) or the **REST API**.

Throughout, `TOKEN` is a Bearer access token from login:

```bash
BASE=http://localhost/api/v1
TOKEN=$(curl -s -X POST $BASE/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"admin@yourco.com","password":"…"}' | jq -r .access_token)
auth=(-H "Authorization: Bearer $TOKEN")
```

## 1. Sign in

Console: enter email + password. If MFA is enrolled you'll be asked for a 6-digit
code (or a recovery code). If OIDC/LDAP are configured, use the **SSO** button or
the **Directory** tab.

## 2. Organize access (users & roles)

GuardRail ships five system roles: **Super Admin, Organization Admin, Auditor,
Operator, Read-only**. Create users and assign roles:

```bash
curl -s "${auth[@]}" -X POST $BASE/users -H 'Content-Type: application/json' \
  -d '{"email":"op@yourco.com","password":"strong-pass-12+","role_ids":["<operator-role-id>"]}'
```

Roles come from a granular permission catalogue (`device:connect`, `session:read`,
`approval:decide`, `log:read`, …). The UI hides actions the principal can't perform.

### Teams — which devices each department reaches

A role answers *what may this person do*. A team answers *which devices they may
do it to*. They are separate on purpose: expressing "IT reaches IT kit, security
reaches security kit" with roles alone means a role per department per job
function — IT Operator, IT Auditor, Security Operator, Security Auditor — and
another pair every time either list grows.

Create a team, put people in it, and grant it asset groups:

```bash
# One team per department.
curl -s "${auth[@]}" -X POST $BASE/teams -H 'Content-Type: application/json' \
  -d '{"name":"IT","description":"Network and server estate"}'

curl -s "${auth[@]}" -X PUT $BASE/teams/<team-id>/members \
  -H 'Content-Type: application/json' -d '{"user_ids":["<user-id>", "..."]}'

curl -s "${auth[@]}" -X PUT $BASE/teams/<team-id>/grants \
  -H 'Content-Type: application/json' -d '{
    "groups": [{"asset_group_id":"<it-group-id>", "level":"connect"}],
    "device_types": [{"device_type":"switch", "level":"manage"}]
  }'
```

**Levels.** `view` < `connect` < `manage`.

| Level | The devices are | A session can be brokered | They can be edited |
|---|:--:|:--:|:--:|
| `view` | listed | — | — |
| `connect` | listed | ✔ | — |
| `manage` | listed | ✔ | ✔ |

A level is a **ceiling on reach, never a grant of capability**. Granting an
Auditor `manage` over a group gives them nothing new, because the Auditor role
holds no `device:write`. Reach and permission are ANDed: "can I do X to device D"
is always *does my role permit X* **and** *does my reach cover D at a level that
covers X*.

**Devices you do not reach are not listed at all** — not in the inventory, the
dashboard counts, or `/status/devices`. This is what makes a `view` grant
meaningful: it is the level that says "you may see this and not touch it", as
distinct from not knowing it exists.

**Flexibility.** Teams overlap freely and reach is the **union**, taking the
highest level per device — so adding somebody to a second team can never remove
what the first gave them. That is what covers the awkward cases:

- The security team can be granted `view` over the IT tree and `manage` over its
  own, so it can see the firewalls it audits without being able to log into them.
- An admin or platform team gets `all_devices_level` — a blanket grant over
  everything, *including devices registered later*. Enumerating such a team
  against every group instead produces a grant that silently stops covering new
  kit as the estate grows.
- A group grant covers the groups **nested inside it**, so the tree can be
  reorganised without silently revoking access.

Somebody in no team is unaffected: their reach is whatever their roles already
gave them, which is how every deployment behaved before teams existed.

## 3. Register a device (target admin UI)

A "device" is any HTTP/HTTPS management interface — firewall, switch, WLC,
hypervisor, load balancer, storage, etc.

```bash
curl -s "${auth[@]}" -X POST $BASE/devices -H 'Content-Type: application/json' -d '{
  "name":"Edge-FW","vendor":"Fortinet","device_type":"firewall",
  "host":"10.0.0.10","port":443,"scheme":"https","verify_tls":true,
  "requires_approval":false
}'
```

## 4. Store a credential in the vault (write-only)

Secrets are sealed with **envelope encryption** (AES-256-GCM DEK per secret,
wrapped by the KEK). They are **never returned** by the API and never reach the
browser.

```bash
curl -s "${auth[@]}" -X POST $BASE/credentials -H 'Content-Type: application/json' -d '{
  "name":"fw-admin","type":"password","username":"admin",
  "injection":"basic","secret":"the-device-password"
}'
# then bind it to the device (device⇄credential binding)
```

Injection methods: `basic` (HTTP Basic), `header` (Authorization/custom),
`form` (login-form post), or `none`.

## 5. Connect — the core flow

Click **Connect** on a device (or `POST /devices/{id}/connect`). GuardRail:

1. authenticates you and checks `device:connect`,
2. creates an **audited session** and time-boxes it,
3. resolves the device credential **just-in-time** (held in memory only),
4. launches a **credential-injecting reverse proxy** — the secret is injected
   **server-side**, so the user's browser never sees it,
5. records the session (event timeline) for playback and audit.

If the device has `requires_approval: true`, connect returns **202
pending_approval** instead, and an approval request is created.

## 6. Approvals

Approvers see pending requests under **Approvals** (`GET /approvals?status=pending`)
and approve/deny them. Approvals are **one-time** or **windowed** and auto-expire.
Once approved, the requester starts the session (`POST /sessions/{id}/start`)
within the granted window.

## 7. Monitor & terminate live sessions

**Sessions** shows active sessions (auto-refreshing). Anyone with
`session:terminate` can force-terminate; the kill is signalled across API replicas
via Redis so the proxy closes immediately.

## 8. Enable your second factor (MFA)

**Security** → *Set up authenticator*: scan the QR / enter the secret in any TOTP
app, confirm a code, and **save the 10 recovery codes** (shown once). After this,
your logins require the second factor. You can regenerate codes or disable MFA
from the same page.

## 9. Notifications

Create channels (webhook, Slack, email) so events like `approval.requested` /
`approval.decided` fan out. Delivery is via a transactional outbox with retries.

## 10. Audit, search, reports

- **Audit Log**: a tamper-evident, **hash-chained** record of every privileged
  action. Filter by action/result/time (`GET /audit`, needs `log:read`).
- **Global search**: the header search box hits `GET /search` across users,
  devices, and sessions.
- **Reports**: export the audit log or access-session history as CSV
  (`POST /reports {"type":"audit"|"access"}`, needs `report:read`).

## Security guarantees, in one place

- Device credentials are **never exposed** to users — injected server-side, held
  in memory only, and audited as `credential.use`.
- **Two-layer tenant isolation**: application scope + PostgreSQL Row-Level
  Security via a non-superuser DB role.
- **Tamper-evident audit**: append-only, per-org SHA-256 hash chain (the app role
  has no UPDATE/DELETE grant on the audit table).
- **Argon2id** passwords, **JWT + rotating refresh tokens with reuse detection**,
  brute-force throttle + lockout, **TOTP MFA**, and OIDC/LDAP federation.
