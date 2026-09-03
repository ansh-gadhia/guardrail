# SIEM single sign-on — the GuardRail side

The SIEM authenticates the analyst. GuardRail never sees a password, never runs a
redirect dance with the SIEM, and never calls back to ask a question. The SIEM
mints a short-lived signed assertion — an **exchange token** — and GuardRail
trades it for a session of its own.

It is deliberately not OIDC. GuardRail *has* OIDC (`GUARDRAIL_OIDC_*`), and that
is the right answer when the identity provider is an OIDC provider. Here there is
no authorization code, no redirect back to the issuer, no client secret and no
discovery document. One JWT, one POST, one session back. What it costs the SIEM
is an HTTP endpoint, a JWT library and a key.

**Status:** implemented and deployed. Inert until the SIEM starts sending tokens —
every setting defaults to the behaviour of a deployment that has never heard of
the SIEM, which is what let this ship ahead of the SIEM's half.

---

## 0. The short version

**Three values turn this on**, the same three the SIEM's other consumers already
have: the JWKS URL, the certificate, and (only if they still sign HS256) the
shared secret.

```bash
sudo /opt/guardrail/siem-sso.sh https://10.200.10.23:3000/api/sso/jwks.json \
     --cert /path/to/siem-jwks.pem \
     --secret a1b2c3d4...
```

Drop `--cert` and it fetches the certificate itself and shows you the fingerprint
before trusting it. Drop `--secret` and it uses the JWKS alone, which is the
better place to end up (§12).

GuardRail also answers to the **unprefixed** env names, so a working block from
another consumer can be pasted straight into `/opt/guardrail/.env`:

```
SIEM_JWKS_URL=https://10.200.10.23:3000/api/sso/jwks.json
SIEM_JWKS_CA_BUNDLE=/etc/guardrail/siem/jwks-ca.pem
SIEM_SSO_SECRET=a1b2c3d4...
```

One catch if you go that route: the path must be one the **API container** can
read. `deploy/siem/` is bind-mounted at `/etc/guardrail/siem`, so put the PEM
there. A path from another product's filesystem exists on the host and nowhere
the API can see it — which is why the script copies it for you.

Either way it pins the certificate where the API can read it, proves the key set
fetches through it, writes the `.env` keys, recreates the API with the new
environment and checks the result. `siem-sso.sh status` shows what is configured;
`siem-sso.sh off` turns it off again.

You do not need to look up an organization UUID: a single-tenant deployment has
exactly one right answer and GuardRail uses it. (`--org <slug>` if you run more
than one tenant here — it will refuse to guess and name them.)

Then on the SIEM side: mint a token and redirect the browser to
`https://<console>/auth/sso#token=<token>`. That is the whole integration.

Everything below is what that command does, why each piece is the way it is, and
what to tell the SIEM's engineers.

---

## 1. The shape of it

| Flow | Who calls | Proof | Result |
|---|---|---|---|
| **A — open the console** | the analyst's browser | exchange token in the redirect fragment | a logged-in GuardRail session |
| **B — read device state** | the SIEM's server | a GuardRail API token | the device inventory and its liveness |

Flow A is the integration. **Flow B needs nothing new** — see §9; GuardRail
already has the better answer for it, and it is not this.

- **Endpoint:** `POST /api/v1/auth/sso/exchange` — public, no `Authorization` header
- **Callback page:** `https://<console>/auth/sso#token=<exchange-token>`
- **Issuer string:** `cybersentinel-siem` (configurable)
- **Audience:** `guardrail-pam` — **GuardRail's own**, not shared with any other consumer
- **Token life:** ~30 s, single use

---

## 2. What GuardRail needs from the SIEM

Seven things. Items 1–4 are required; 5–7 make it work properly rather than
merely work.

1. **A JWKS endpoint over HTTPS**, and **the TLS certificate it presents** (or the
   internal CA that signed it). You already have both.
2. **`kid` on every token**, so a rotation does not need a flag day.
3. **`aud: "guardrail-pam"`** added to the tokens it mints *for GuardRail*.
   A value of its own — not the one it uses for the DLP. Sharing an audience
   across two consumers is the same as not checking it.
4. **`purpose: "sso_exchange"`** and **a fresh `nonce` per token**, with **`exp`
   about 30 seconds out**.
5. **A stable `sub`** — the SIEM's own immutable user id, *not* the email address.
   This is the single most consequential ask on the list; §6 explains why.
6. **`email`** — required to create an account, optional once one exists.
7. **`role` and `access`**, with the access mode stated explicitly rather than
   implied. An absent `access` is treated as read-only, because between over- and
   under-granting on a claim nobody made, only one of the two is safe.

### What the SIEM has to build

```
1. A "Open in GuardRail" control on its own console.
2. On click: mint a token (below) and redirect the browser to
     https://<guardrail-host>/auth/sso#token=<token>
   Fragment (#), not query string (?). See §7.
3. Nothing else. No callback to handle, no client secret to store,
   no token to refresh, no GuardRail credential to hold.
```

### The token

```jsonc
// header
{ "alg": "RS256", "typ": "JWT", "kid": "siem-2026-08" }

// payload
{
  // ── required ─────────────────────────────────────────
  "purpose": "sso_exchange",           // exact string
  "iss":     "cybersentinel-siem",  // exact string
  "aud":     "guardrail-pam",          // GuardRail's own audience
  "sub":     "7f31c0a2-…",             // the SIEM's immutable user id — the join key
  "nonce":   "9f2c4e…",                // unique per token (uuid4 hex is fine)
  "exp":     1786000030,               // now + 30s

  // ── identity ─────────────────────────────────────────
  "email":     "analyst@corp.com",     // required to CREATE an account
  "username":  "jdoe",                 // optional, cosmetic
  "full_name": "J. Doe",               // optional, cosmetic ("name" also accepted)

  // ── privileges ───────────────────────────────────────
  "role":   "L2-Analyst",              // administrator | L3-Analyst | L2-Analyst | L1-Analyst | read-only
  "access": "read-write",              // read-write | read-only  (absent ⇒ read-only)

  // ── optional ─────────────────────────────────────────
  "amr": ["pwd", "mfa"]                // only consulted if TRUST_AMR is on; off by default
}
```

| Claim | Rule | If absent |
|---|---|---|
| `purpose` | must equal `sso_exchange` | 401 wrong purpose |
| `iss` | must equal the configured issuer | 401 wrong issuer |
| `aud` | must equal `GUARDRAIL_SIEM_SSO_AUDIENCE`, and must be **present** | 401 |
| `sub` | the join key, immutable | falls back to `email` as the key |
| `nonce` | fresh per token; remembered until after the token expires | 401 missing nonce |
| `exp` | required outright; also capped by `MAX_TOKEN_AGE` | 401 — a token with no `exp` is rejected, not treated as eternal |
| `email` | needed to create; optional to sign in an account `sub` already matches | 401 only on the provisioning path |
| `role` | SIEM vocabulary, normalised (§5) | falls to `DEFAULT_ROLE`; **sync leaves the existing role alone** |
| `access` | `read-write` / `read-only` | `read-only` — silence is never taken as permission |

---

## 3. What GuardRail does when a token arrives

Order is load-bearing. Nothing is read out of the token before its signature has
vouched for it, and every step separates *"your token is bad"* (**401**) from
*"GuardRail cannot check right now"* (**503**).

1. **Is SSO configured at all?** Needs key material *and* a provisioning
   organization. → `503 SSO Not Configured`
2. **Read the unverified header** — only to learn `alg` and `kid`. → 401
3. **Route to key material by algorithm family.** Asymmetric → the JWKS key named
   by `kid`. Symmetric → the shared secret, if one is configured. Anything else,
   `none` included → 401.
4. **Resolve the key.** Cached key set (10 min). An unknown `kid` forces one
   refetch, rate-limited to once per 30 s so a stream of unknown-kid tokens
   cannot make GuardRail an amplifier aimed at the SIEM. → 401 / 503
5. **Verify the signature** with the **single routed algorithm**, never a list.
6. **Audience presence, checked by hand** against the verified claims.
7. **Bound the claimed lifetime.** `exp − now` must not exceed `MAX_TOKEN_AGE`.
8. **Check `purpose`, then `iss`** — exact strings.
9. **Spend the nonce** in Redis, atomically, **before anything is created or
   changed**.
10. **Resolve the person** — `sub` first, `email` second — and reconcile (§6).
11. **Provision or sync** the account (§4, §5).
12. **Refuse a disabled or locked account** — *after* provisioning and sync, so a
    re-enable in the SIEM lands before the gate rather than one sign-in after it.
13. **Ask for GuardRail's own second factor**, if this person enrolled one (§8).
14. **Mint the session** — access + refresh, marked `sso`.

### Two failure postures, deliberately opposite

- **The JWKS fetch fails closed.** A key set that could not be fetched is not
  evidence that a signature is good. Unreachable with nothing cached ⇒ refused
  (503). A **stale-but-real cached set is still served** through a blip, because
  it still verifies genuine tokens — but only when it actually holds the `kid`.
  When it does not, "rotated to a key we cannot see" and "kid invented by an
  attacker" are indistinguishable, and 503 is the honest answer.
- **The replay store also fails closed** — and this is where GuardRail departs
  from the DLP, on purpose. The DLP fails *open* on a Redis outage, reasoning
  that a signature and a 30-second expiry still bound the damage. On a
  privileged-access broker they do not bound it enough: the session a replayed
  token opens can connect to a device. Nothing else in the product stops a
  replay, Redis is already a hard dependency (it is in the readiness probe), so a
  deployment that cannot reach it is not serving logins anyway — failing open
  would buy an availability that does not exist.

---

## 4. Accounts

### Just-in-time provisioning (`JIT_PROVISION`, default on)

The alternative is the SIEM holding standing GuardRail administrator credentials
purely to pre-register people — a permanent privileged credential, on a
privileged-access broker, held by a machine, to write rows. Provisioning from the
token removes it.

| Field on create | Source | Note |
|---|---|---|
| `email` | token | required; the login identifier |
| `password` | **none at all** | the account cannot be reached through the password path, so there is deliberately nothing there to attack — not even something random |
| `username` | token | cosmetic; GuardRail does not enforce uniqueness on it |
| `auth_provider` | `siem` | distinct from `oidc`, so "change your password at your provider" names the right one |
| roles | the translation table (§5), after the bar and the ceiling | |
| `siem_sub` / `sso_managed` / `sso_source_role` | token + flow | provenance and ownership |

Two edge cases that are handled rather than assumed away:

- **No `email` on the token ⇒ 401.** You can find a person by `sub` alone; you
  cannot invent one without an address.
- **Concurrent first sign-ins for the same person** ⇒ the create hits the
  uniqueness index, and the loser re-resolves by `sub` then `email` instead of
  failing the sign-in.

### Who owns an account

Every account is either SIEM-owned or locally owned. The boundary is one boolean.

| Event | Ownership after | Effect |
|---|---|---|
| Created by an SSO sign-in | SIEM-owned | role tracks the token |
| Created locally / in the console | local | SSO never rewrites its roles |
| An existing account adopts a `sub` | **unchanged** (stays local) | adopting an identity is not a handover |
| A GuardRail admin edits the roles | local (**detached**) | the local decision wins from then on |

That last row matters more than it looks. Without it, an administrator's change
would last exactly until its subject next signed in and then be silently
reverted — which is worse than refusing the edit outright, because it looks like
it worked.

**So: if a super admin promotes an SSO-provisioned Auditor to Super Admin, does
the next SIEM sign-in put them back to Auditor? No.** The promotion detaches the
account, and it stays promoted. Verified end to end:

```
1. SIEM says L2/read-only          -> Auditor              sso_managed=true
2. super admin sets Super Admin    -> Super Admin          sso_managed=false
3. SIEM still says L2/read-only    -> Super Admin          (unchanged)
```

The same holds in the other direction — a demotion by hand is not undone either.
Whoever touched it last, locally, wins.

### Handing an account back to the SIEM

That detach would otherwise be a **one-way door**: an administrator who edits
somebody's roles for a week-long project has, without being told, permanently
stopped that account tracking the SIEM, and the only way back would be an UPDATE
against the production database.

```
POST /api/v1/users/{id}/sso-resync      # user:write
```

Takes effect on that person's **next** sign-in, and is audited as
`auth.sso.resync` with the roles they held at the time. It is deliberately
explicit rather than automatic: every rule that would re-attach an account by
itself ("when the roles match again", "after N days") silently overwrites a local
decision at a moment nobody chose. Somebody has to say so.

Two refusals: an account that has never signed in through the SIEM (there is no
SIEM role to track, so the flag would arm a rule that can never fire), and the
installation account (handing the one account that can restore the platform to an
external system to overwrite is exactly what that guard is for).

---

## 5. Role translation

A **translation table**, not an identity mapping. The two products do not share a
role vocabulary and should not be made to. Nothing in GuardRail's own RBAC is
added, removed or rewritten — the table only chooses among roles that already
exist.

### Normalisation first

The SIEM may send `L1`, `l1`, `L1 Analyst`, `Tier-1` or `LEVEL_1` and mean the
same thing, and which one it sends can change with a UI relabel nobody thought
was an integration change. Every non-alphanumeric character is stripped, the rest
uppercased, then looked up in an alias table.

```
role    ADMINISTRATOR | ADMIN | SIEMADMIN | SUPERADMIN   -> Administrator
        L1 | L1ANALYST | TIER1 | T1 | LEVEL1             -> L1   (same for L2, L3)
        READONLY | READONLYANALYST | VIEWER | VIEWONLY  -> read-only
access  RW | READWRITE | WRITE | READANDWRITE | FULL | EDIT -> read-write
        RO | READONLY | READ | VIEW | VIEWONLY           -> read-only  (and anything else)
```

### The default table

Every SIEM analyst gets their own GuardRail account, keyed on their own `sub`,
with the role their own token asserts. Ten analysts at four tiers produce ten
accounts at four privilege levels; there is nothing shared between them.

| SIEM role | Access | GuardRail role | Rank | Connect to a device | Kill a session | Watch recordings | Audit log | Manage devices & credentials | Manage users | Approve access |
|---|---|---|---|:--:|:--:|:--:|:--:|:--:|:--:|:--:|
| Administrator | read-write | **Organization Admin** | 50 | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| Administrator | read-only | **Auditor** | 0 | — | — | ✔ | ✔ | — | — | — |
| L3 | read-write | **Operator** | 10 | ✔ | ✔ | ✔ | — | — | — | — |
| L3 | read-only | **Auditor** | 0 | — | — | ✔ | ✔ | — | — | — |
| L2 | read-write | **Operator** | 10 | ✔ | ✔ | ✔ | — | — | — | — |
| L2 | read-only | **Auditor** | 0 | — | — | ✔ | ✔ | — | — | — |
| L1 | read-write | **Read-only** | 0 | — | — | ✔ | — | — | — | — |
| L1 | read-only | **Read-only** | 0 | — | — | ✔ | — | — | — | — |
| read-only | read-write | **Read-only** | 0 | — | — | ✔ | — | — | — | — |
| read-only | read-only | **Read-only** | 0 | — | — | ✔ | — | — | — | — |

The exact permission keys behind each, straight out of `db/seed.sql`:

```
Organization Admin   every permission in the catalogue (22)
Operator             device:connect, device:read, group:read,
                     recording:read, session:read, session:terminate
Auditor              approval:read, device:read, log:read, recording:read,
                     report:read, session:read, user:read
Read-only            device:read, group:read, recording:read, session:read
Super Admin          NEVER granted by SSO — see the bar below
```

Read the two rank-0 rows carefully, because they are not the same thing:
**Auditor** sees the audit log, reports and the user list; **Read-only** sees the
estate and its sessions and nothing about who did what. An L1 who needs the audit
trail should be mapped to Auditor with the override, not left on the default.

`Rank` is the approval hierarchy: an approver must outrank a requester
**strictly**. So an Operator (10) cannot approve another Operator's access
request — only an Organization Admin (50) or a super admin can. Two Operators
signing each other's work is not a hierarchy, which is the realistic failure the
strict comparison is there to prevent.

Three cells worth explaining:

- **Administrator/read-write is Organization Admin, never Super Admin.** Super
  Admin is not "a bigger administrator" — it is the role that turns row-level
  security *off*, so it reads and writes every tenant on the deployment. See
  the bar below.
- **L3 and L2 both land on Operator.** That is a refusal to invent a role, not an
  oversight: GuardRail seeds nothing between Operator (rank 10) and Organization
  Admin (rank 50), so there is no "an L3 who can do slightly more" to promote
  into. If you want the distinction, create a role, give it a rank between the
  two, and point the override at it.
- **read-only never maps to a role that can connect to a device.** On a broker
  whose whole job is standing between people and privileged access, "read-only"
  has to mean it.
- **A `read-only` role claim wins over a `read-write` access claim.** The role is
  the tier; the access mode only narrows it. An account the SIEM ranks below its
  analyst tiers does not become an Operator because a second claim disagrees —
  the two disagreeing is exactly the case where taking the lower one is the point.

### The bar, and the ceiling

**The bar: the Super Admin role is unreachable through SSO. Always.** Not a
default, not a setting — the code refuses it even when the override explicitly
names it, and falls back to the default role. A rule a sufficiently privileged
setting can switch off is not a rule, and the failure it prevents is "anyone who
can forge a token owns every tenant on the installation".

**The ceiling** (`MAX_ROLE`) is the configurable part, on top. Once the token can
pick a role, a *forged* token can pick a role; set the ceiling to `Operator` and
no SSO sign-in reaches administration whatever any claim says.

### Overriding it as data

```
GUARDRAIL_SIEM_SSO_ROLE_MAP='{"L3": {"rw": "Senior Operator", "ro": "Auditor"},
                              "L1": "Read-only"}'
```

A bare string is shorthand for both access modes. Malformed JSON falls back to
the built-in table and logs loudly — a misconfiguration must not hand everybody
an administrator's role, and must not lock everybody out. Visible and harmless
beats catastrophic in either direction.

### Never leave somebody with no roles

`DEFAULT_ROLE` is `Read-only`, not empty. GuardRail's OIDC and LDAP federation
provision with *no* roles, and that is right for them — an administrator is
expected to grant access and the person is told to wait. Here the SIEM is
asserting that this person is an analyst *right now*, and a GuardRail account
with no roles signs in successfully to a console where every page is empty and
every action is refused. That reads as the product being broken rather than the
person being unprivileged.

---

## 6. Key on `sub`, not on email

Email is a display attribute that changes: a surname changes, a company migrates
domains, an address is corrected. An account keyed on it is orphaned by every one
of those — the next sign-in finds nothing, provisions a *second* account, and the
original's roles, approval rank and history belong to somebody who can no longer
reach them. Nothing errors at any point. It surfaces weeks later as "why can't I
get to anything", by which time the trail from cause to effect is cold.

Lookup is `sub` → the account that has claimed this SIEM identity; failing that,
`email` → so accounts predating SIEM sign-in are found rather than duplicated.
Then GuardRail reconciles:

- **Backfill** — matched by email with no `siem_sub` stored ⇒ adopt the token's
  `sub`. From then on the account is found by subject and survives a rename. No
  migration, no coordinated cutover, no script: every account adopts its identity
  on its owner's next sign-in, and accounts whose owners never use the SIEM
  simply never adopt one.
- **Rename** — matched by `sub` with a different email ⇒ update the stored
  address. Trusted only because the match came from the subject; an
  email-matched row tells you nothing new about its own email, which is why the
  backfill path deliberately does not do this.
- **Collision** — if another account in the tenant already holds that address,
  log and skip. Failing an entire sign-in over a display attribute is the wrong
  trade.

Reconciliation is never fatal.

---

## 7. The browser handoff

```
https://<console-host>/auth/sso#token=<exchange-token>      ← preferred
https://<console-host>/auth/sso?token=<exchange-token>      ← accepted fallback
```

> **Fragment, not query string.** A URL fragment is never transmitted to a
> server. A query string is — so `?token=…` is written verbatim into Traefik's
> access log, which is rotated, shipped somewhere and kept far longer than the
> thirty seconds the credential is alive. It also lands in browser history and in
> the `Referer` of whatever the page loads next. The query string is accepted so
> an issuer already redirecting that way keeps working, and has a strictly better
> option to move to.

The callback page reads the fragment, **scrubs it from the address bar via
`history.replaceState` before attempting the exchange**, POSTs it, and replaces
the history entry with `/`. On failure it renders the server's `detail` string
verbatim — those strings are written to be read by whoever is wiring this up, and
replacing them with "Sign-in failed" throws away the only diagnosis they get.

It reuses the sign-in page's backdrop on purpose: a differently-styled
interstitial makes signing in look like a flash through some third product.

---

## 8. Second factor, and the network policy

Two defaults here run the **opposite way to the DLP's**, and both deliberately.

**GuardRail still asks for its own second factor** (`TRUST_AMR=false`). If the
person has enrolled TOTP in GuardRail, an SSO sign-in returns the same MFA
challenge a password sign-in does, and the console shows the same screen. The
marker that says "this sign-in came from the SIEM" is carried inside the signed
challenge, so the session minted on the far side of the code is still a
SIEM-vouched one.

**And they are offered one on arrival.** An account provisioned by the SIEM has
no password, so `must_change_password` is false and the first-run flow — which is
where the two-factor offer lives — used to be skipped entirely. Every analyst
arriving through single sign-on went straight into the console having never been
asked, which is backwards: they are exactly the people it reaches privileged
devices on behalf of.

The console now runs **one rule for both kinds of account**: somebody signing in
for the first time is offered a second factor, and everybody else goes straight
in. A SIEM account sees the same first-run page a locally created one does, minus
the password step it has nothing to do with.

| | Local account | SIEM account |
|---|---|---|
| First sign-in | password step, then the two-factor offer | the two-factor offer |
| Offer dismissed | into the console | into the console |
| Later sign-ins | straight in | straight in |
| Once a factor is confirmed | challenged at sign-in | challenged at sign-in |

Offered **once**, not on every sign-in: the prompt that comes back forever is the
one people learn to click past, and anybody who declined can turn it on from
Account → Two-factor whenever they choose. A temporary password is the one thing
that does keep reappearing, because it is not optional.

The console reads three fields from the principal — `first_login`, `mfa_enabled`
and `auth_provider` — on every token response and on `/auth/me`. `first_login` is
derived from `last_login_at`, so a token refresh correctly reports false:
rotating a token is not a sign-in, and re-offering every fifteen minutes is the
nagging this avoids. "The
SIEM says they did MFA" and "this person just proved possession of a factor
GuardRail knows about" are different claims, and only the second survives the
SIEM being wrong — a forged exchange token asserts `amr` exactly as easily as it
asserts a role. Set `TRUST_AMR=true` only if you would also accept the SIEM
asserting somebody's role, which you already do, *and* you have decided that
re-prompting is worse than the exposure.

**The source-address policy still applies** (`ALLOWLIST_BYPASS=false`). If an
organization has an IP allowlist, SSO sessions are subject to it like everyone
else. On a broker standing in front of privileged devices that allowlist is doing
real work, and it should not switch itself off as a side effect of enabling
single sign-on.

Turn the bypass on **only** if analysts genuinely sign in from outside the
allowed ranges — because the failure it prevents is a nasty one: the exchange
succeeds, the console loads, and then every single API call returns 403. A
working sign-in attached to a dead console reads as the product being broken.
Exempting only the exchange endpoint would fix the first request and nothing
after it, which is why the marker rides the whole session **and its refresh
token** — otherwise the analyst is signed out fifteen minutes in and the network
gets blamed for a week.

---

## 9. Flow B — the SIEM reading device state

**Nothing new is needed, and you should not build the DLP's version of this.**

The DLP's Flow B has the SIEM run Flow A for a service identity to obtain an
admin session and then call REST. GuardRail already has the better answer:
**API tokens** (`/api/v1/api-tokens`, Super Admin only, `guardrail_pat_…`), which
are revocable from the console, carry an optional expiry, are restricted to
**read** permissions by construction, and need no JWT minting or expiry juggling
on the SIEM's side.

```
GET /api/v1/status/devices
Authorization: Bearer guardrail_pat_…

{ "data": [ { "id", "name", "device_type", "ip", "port",
              "status", "checked_at", "latency_ms" } ],
  "summary": { "total", "online", "offline", "unknown" } }
```

Deliberately narrow: name, type, address and whether the device answered its last
probe. No credentials, no session history, no policy. A dashboard that needs to
know a firewall is up should not be handed the shape of the estate with it.
`checked_at` is reported alongside precisely so a consumer can tell "we looked and
it is up" from "nobody has looked in an hour" — collapsing those is how a monitor
ends up confidently green about a host that died forty minutes ago.

An SSO-vouched session *also* reaches this endpoint (verified), so if the SIEM
would rather use Flow A for it, that works. It just costs more and revokes worse.

**To issue one**, any of:

- `install.sh` already minted one at the end of a fresh install and printed it —
  named `installer-bootstrap`, and it already carries `device:read`.
- **Lost it?** Only its hash is stored, so it cannot be shown again. Mint a
  replacement on the server:

  ```bash
  sudo /opt/guardrail/siem-sso.sh token --name siem-feed
  ```

  It signs in as the super admin (reading the credentials from `.env`, prompting
  when they are stale or a second factor is enrolled), lists the tokens that
  already exist so you do not leave a second standing credential behind by
  accident, and prints the new one once.
- Or in the console: **Security → API tokens** (super admin only).

Tokens are restricted to **read** permissions by construction — `device:read` is
the one the device feed needs. Revoke an old one from the console; revocation is
immediate and everywhere.

---

## 10. Configuration

Every setting is optional and every default reproduces the behaviour of a
deployment that has never heard of the SIEM.

| Setting | Default | What it does |
|---|---|---|
| `GUARDRAIL_SIEM_JWKS_URL` | — | **The one required setting.** Where the SIEM publishes its public keys. HTTPS only. Written by `siem-sso.sh`. |
| `GUARDRAIL_SIEM_SSO_ORG` | — | Which organization SIEM users land in, as a **slug** or a UUID. Empty means "the only organization on this deployment" — right on nearly every install. With several tenants it refuses to guess and names them. Falls back to `GUARDRAIL_FEDERATION_ORG_ID`. |
| `GUARDRAIL_SIEM_JWKS_CA_BUNDLE` | — | PEM that verifies the JWKS host's TLS certificate (§11). Needed for any self-signed SIEM. |
| `GUARDRAIL_SIEM_SSO_ISSUER` | `cybersentinel-siem` | Exact `iss` |
| `GUARDRAIL_SIEM_SSO_AUDIENCE` | `guardrail-pam` | Exact `aud`. Do not share it with another consumer. |
| `GUARDRAIL_SIEM_SSO_SECRET` | — | Enables HS256. **Leave empty** (§12). |
| `GUARDRAIL_SIEM_JWKS_CACHE_TTL` | `10m` | Key-set freshness; an unknown `kid` forces one early refetch |
| `GUARDRAIL_SIEM_SSO_CLOCK_LEEWAY` | `1m` | Skew tolerance on `exp`/`nbf`; also extends nonce retention |
| `GUARDRAIL_SIEM_SSO_MAX_TOKEN_AGE` | `10m` | Longest validity a token may *claim* |
| `GUARDRAIL_SIEM_SSO_NONCE_FLOOR` | `5m` | Floor on nonce retention; the real value comes from the token |
| `GUARDRAIL_SIEM_SSO_NONCE_CEILING` | `1h` | Ceiling on the same |
| `GUARDRAIL_SIEM_SSO_JIT_PROVISION` | `true` | Create the account on first sign-in instead of 401-ing |
| `GUARDRAIL_SIEM_SSO_SYNC_ON_LOGIN` | `true` | Re-apply the mapped role to SIEM-owned accounts |
| `GUARDRAIL_SIEM_SSO_DEFAULT_ROLE` | `Read-only` | Role for a sign-in with no recognised `role` claim |
| `GUARDRAIL_SIEM_SSO_MAX_ROLE` | — | Ceiling on any SSO-derived role. Super Admin is barred regardless. |
| `GUARDRAIL_SIEM_SSO_ROLE_MAP` | — | JSON override of the translation table |
| `GUARDRAIL_SIEM_SSO_TRUST_AMR` | `false` | Accept the SIEM's word instead of GuardRail's own second factor (§8) |
| `GUARDRAIL_SIEM_SSO_ALLOWLIST_BYPASS` | `false` | Exempt SSO sessions from the source-address policy (§8) |

> **Containerised deployment trap.** A setting only reaches the running service if
> it is in the `environment:` block of `docker-compose.yml`. A field that exists
> in Go config but is missing from that block is permanently stuck at its
> default, silently, with nothing anywhere saying so. All of the above are listed
> there. Related: after changing one, `docker compose up -d api` rather than
> `restart` — a restart reuses the old environment.

### Nonce retention derives from the token

Not from a constant. A flat retention ("60 s, double the 30 s TTL") is correct
only for the clock leeway it was written against — widen the leeway later, in a
different file, for a perfectly good reason, and the arithmetic silently breaks:
the token stays valid past the moment its nonce was forgotten, and a replay
window opens that no line of code announces. Retention is `exp + leeway − now`,
floored and capped. The cap can never be what reopens the window, because
`MAX_TOKEN_AGE` refuses an over-long token before retention is ever computed.

---

## 11. Pinning the JWKS fetch

The JWKS fetch is the trust anchor for every SIEM-vouched sign-in. Whoever can
answer that URL chooses the public key GuardRail will accept, and thereafter
mints tokens it treats as genuine — turning "needs the SIEM's private key" into
"needs to be on the network path".

A SIEM on a private network almost always presents a self-signed certificate, so
the fetch fails closed on a fresh deployment. **That is correct, and the escape
hatch is a pinned certificate, not a disabled check.** There is deliberately no
verify-off switch.

`siem-sso.sh` does all of this for you, including showing you the fingerprint and
asking before it trusts anything. By hand:

```bash
# On the GuardRail server:
openssl s_client -connect siem.internal:443 -showcerts </dev/null 2>/dev/null \
  | openssl x509 -outform PEM > /opt/guardrail/deploy/siem/jwks-ca.pem
openssl x509 -in /opt/guardrail/deploy/siem/jwks-ca.pem -noout -subject -dates -fingerprint
# then, in /opt/guardrail/.env:
#   GUARDRAIL_SIEM_JWKS_CA_BUNDLE=/etc/guardrail/siem/jwks-ca.pem
```

The script confirms the fingerprint with a person on purpose: fetching and
trusting in one silent step is trust-on-first-use against whoever answered that
address, which is most of what pinning was meant to prevent. Check it against
what the SIEM's owner tells you it should be.

`deploy/siem/` is bind-mounted read-only into the API container at
`/etc/guardrail/siem`, so the env var names the **in-container** path.

Three consequences to plan for:

- The certificate must match the host in the JWKS URL, so that name or IP has to
  be in its SAN.
- If the path is named but missing or unreadable, GuardRail **refuses the whole
  SSO configuration** rather than falling back to the system trust store. A trust
  anchor that silently disappears is worse than one that never worked.
- **GuardRail stops trusting the SIEM the day that certificate expires**, and the
  symptom is "SSO stopped working" with nothing else broken. Put the expiry in a
  calendar.

---

## 12. Why not a shared secret

`GUARDRAIL_SIEM_SSO_SECRET` exists so a SIEM that cannot yet sign asymmetrically
is not blocked. It should be empty, and the API logs a warning on every boot
while it is not.

Under a shared secret GuardRail holds a key that can **forge** the SIEM's tokens,
not merely verify them. Combined with just-in-time provisioning, a leak of that
one config value does not impersonate an existing analyst — it mints a *new*
account at whatever role the forger writes into the claim. Under RS256 GuardRail
holds only a public key: a total compromise of its configuration yields nothing
that can sign anything, and the SIEM rotates keys without a flag day because
every token names its own.

**Cutover with no outage:** set `JWKS_URL` while the secret is still set — both
work, and the token's own signed `alg` routes verification. When every issuer has
moved, clear the secret; HS256 tokens are then rejected outright rather than
quietly still working. That is a config action, not a release.

**Why routing on `alg` is safe here.** Routing on an attacker-visible header is
normally how an algorithm-confusion downgrade starts: take the published RSA
public key, sign HS256 using its bytes as the "secret", and hope the verifier
checks an HMAC with a key it believed was for RSA. Three rules stop it, and all
three are load-bearing:

1. The two paths use **disjoint key material** — the symmetric path never touches
   anything derived from the key set.
2. The algorithm list handed to the parser is always the **single routed
   algorithm**, never the union of both families, so a token can never nominate a
   verifier that was not intended for it.
3. Accepted families are **enumerated explicitly**, so none is reachable by
   accident and `none` is not a spelling of anything.

Both are covered by tests (`TestSSOVerify_RejectsAlgorithmConfusion`,
`TestSSOVerify_SymmetricPathUsesDisjointKeyMaterial`).

---

## 13. Error contract

401 means the token is bad and retrying will never work. 503 means GuardRail
could not check and a retry is reasonable. Every string is written to be shown to
a person.

| Status | Detail | Cause / fix |
|---|---|---|
| 503 | SSO is not configured | no JWKS URL, or no `FEDERATION_ORG_ID` |
| 503 | SSO temporarily unavailable | JWKS unreachable with nothing cached, or Redis down |
| 401 | the token header could not be read | malformed token |
| 401 | unsupported signing algorithm `X` | outside the accepted families (`none` lands here) |
| 401 | `RS256` presented but no SIEM JWKS URL is configured here | SIEM moved to asymmetric ahead of GuardRail |
| 401 | symmetric signing is not accepted here | secret cleared; the SIEM must sign from its JWKS |
| 401 | no key matches kid `K` | SIEM signed with a key it does not publish |
| 401 | token carries no kid and the key set holds N keys | send `kid` once more than one key is published |
| 401 | the exchange token has expired | clock skew, or a TTL too tight for the round trip |
| 401 | the token carries no `aud` claim | address the token to this consumer |
| 401 | claims N of validity; the maximum here is M | the handoff token is being minted like a session token |
| 401 | wrong purpose / wrong issuer | claim typo — both are exact strings |
| 401 | this exchange token has already been used | nonce reuse; generate a fresh one per token |
| 401 | the token carries no nonce | it cannot be made single-use |
| 401 | no GuardRail account and JIT provisioning is switched off | provision the account, or turn JIT on |
| 401 | the token carries no email claim | cannot create an account without an address |
| 401 | Account Inactive / Account Locked | re-enable in GuardRail, then retry |
| 429 | rate limit exceeded | the exchange endpoint is throttled per source address |

Audit events emitted: `auth.sso` (every attempt, success or refusal),
`auth.sso.provision`, `auth.sso.sync`, `auth.sso.reconcile`. Every one is filed
under the provisioning organization even when no account was resolved — a stream
of rejected exchange tokens is exactly what that tenant's own administrator needs
to see, and a row with a NULL organization is visible to super admins only.

---

## 14. Standing this up on a new server

### On the GuardRail server

```bash
# 1. Install as normal.
curl -fsSL https://…/install.sh | sudo bash

# 2. Wire up SSO. That is the whole step.
sudo /opt/guardrail/siem-sso.sh https://10.200.10.23:3000/api/sso/jwks.json
```

It shows you the certificate and its fingerprint, asks once, and then does the
rest — pins it, proves the key set fetches through it, writes the `.env` keys,
recreates the API (`up -d`, never `restart` — a restart reuses the old
environment) and confirms `siem_sso: true`.

Useful variants:

```bash
sudo /opt/guardrail/siem-sso.sh <url> --max-role Operator   # cap what SSO can grant
sudo /opt/guardrail/siem-sso.sh <url> --org acme            # multi-tenant deployments
sudo /opt/guardrail/siem-sso.sh <url> --secret <hex>        # also accept HS256 (§12)
sudo /opt/guardrail/siem-sso.sh status                      # what is configured now
sudo /opt/guardrail/siem-sso.sh off                         # turn it off
```

Upgrading an existing server needs nothing by hand: `install.sh` adds every key
blank (blank keeps SSO off) and drops `siem-sso.sh` alongside `migrate-data.sh`.

If you would rather do it by hand, §11 has the openssl commands and the keys are
listed in §10 — the script is a convenience, not a requirement.

### On the SIEM side

1. Publish a JWKS endpoint over HTTPS with a `kid` on every key.
2. Add `aud: "guardrail-pam"` to the tokens minted for GuardRail.
3. Send a stable `sub` — the SIEM's own immutable user id, not the email.
4. Send `role` + `access`, with the access mode stated explicitly.
5. Send a fresh `nonce` per token and an `exp` about 30 s out.
6. Redirect to `https://<guardrail-host>/auth/sso#token=<token>` — fragment.

### First sign-in checklist

- [ ] `siem-sso.sh status` shows the URL, the pinned certificate and its expiry
- [ ] `GET /api/v1/auth/providers` reports `"siem_sso": true`
- [ ] The API log line `SIEM single sign-on enabled` shows `jwks_pinned: true`
      and the organization it resolved
- [ ] A real handoff lands on the dashboard, not on an error card
- [ ] The account appears in the console with the role you expected
- [ ] `auth.sso` and `auth.sso.provision` are in the audit log
- [ ] Deliberately replay the same URL — it must be refused

### Two things to decide before you go live

- **`MAX_ROLE`.** Consider setting it to `Operator` so no SSO sign-in can reach
  administration even with a forged token. Administrators then get their
  GuardRail roles from a GuardRail administrator.
- **`ALLOWLIST_BYPASS`.** If the tenant has an IP allowlist *and* analysts sign in
  from outside it, turn this on — otherwise they get a working sign-in and a dead
  console (§8).
