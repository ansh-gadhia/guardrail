# GuardRail — API Design

- **Style:** REST over HTTPS, JSON, versioned under `/api/v1`. Internal
  service-to-service (API ↔ Gateway) uses gRPC.
- **Source of truth:** OpenAPI 3.1 at `backend/api/openapi.yaml`, served at
  `/api/v1/openapi.json` and Swagger UI at `/api/v1/docs`.
- **Auth:** `Authorization: Bearer <access JWT>` for API calls; refresh token in
  an `HttpOnly; Secure; SameSite=Strict` cookie. CSRF double-submit token for
  cookie-authenticated state-changing routes.
- **Errors:** RFC 9457 `application/problem+json`
  `{type,title,status,detail,instance,errors[]}`.
- **Pagination:** cursor-based `?limit=&cursor=`; responses include
  `{data,next_cursor}`. **Filtering/sort:** `?filter[field]=&sort=-created_at`.
- **Idempotency:** `Idempotency-Key` header honored on POSTs that create
  sessions/approvals.
- **Rate limits:** per-IP + per-user token buckets in Redis; `429` with
  `Retry-After`. Auth endpoints have stricter buckets.

## Conventions
- IDs are UUIDv7 strings. All list endpoints are tenant-scoped implicitly by the
  caller's org (super-admin may pass `?organization_id=` on admin routes).
- Every mutating endpoint emits an audit event.

## Endpoint map (v1)

### Auth & session
```
POST   /auth/login                 email+password -> {mfa_required, mfa_token} | tokens
POST   /auth/mfa/verify            complete MFA challenge (TOTP or recovery) -> tokens
POST   /auth/refresh               rotate refresh -> new access token
POST   /auth/logout                revoke current session
GET    /auth/me                     current principal + permissions
GET    /auth/providers             enabled login methods {local, ldap, oidc, siem_sso}
POST   /auth/ldap/login            directory bind -> tokens (JIT provision)
GET    /auth/oidc/start            begin OIDC (PKCE) -> 302 to IdP + txn cookie
GET    /auth/oidc/callback         IdP redirect -> exchange + tokens
POST   /auth/sso/exchange          SIEM exchange token -> tokens (see SIEM_SSO.md)
```

`/auth/sso/exchange` is public and takes `{"token": "<jwt>"}`. It answers 401
when the token is bad and no retry will help, and 503 when GuardRail could not
verify it right now — the split is part of the integration contract, not a
formality. See [SIEM_SSO.md](SIEM_SSO.md).

### MFA (self-service, authenticated)
```
GET    /mfa                         status {enabled, confirmed, recovery_codes_left}
POST   /mfa/totp/enroll             begin TOTP enrollment -> {secret, provisioning_uri}
POST   /mfa/totp/confirm            confirm a TOTP code -> {recovery_codes}
POST   /mfa/recovery-codes          regenerate recovery codes
DELETE /mfa                         disable the second factor
```

### Organizations & IAM
```
GET    /organizations                         (super-admin)
POST   /organizations
GET    /organizations/{id}
PATCH  /organizations/{id}
GET    /users            POST /users
GET    /users/{id}       PATCH /users/{id}     DELETE /users/{id}
POST   /users/{id}/roles         PUT roles set
GET    /roles            POST /roles           PATCH/DELETE /roles/{id}
GET    /permissions                            (catalogue)
```

### Assets
```
GET    /devices?filter[vendor]=&filter[tag]=&sort=name
POST   /devices          GET/PATCH/DELETE /devices/{id}
POST   /devices/{id}/credentials         bind credential
GET    /asset-groups     POST/PATCH/DELETE ...     (nested/dynamic)
```

### Vault
```
POST   /credentials       (write-only secret; never returned in plaintext)
GET    /credentials/{id}  (metadata only: type, username, rotated_at)
PATCH  /credentials/{id}  rotate / update secret
DELETE /credentials/{id}
```
Secret fields are **write-only**: create/update accept them, no read endpoint
ever returns them.

### Access, approvals, sessions
```
POST   /devices/{id}/connect          -> {status: active|pending_approval, proxy_url?}
GET    /sessions?filter[status]=       list access sessions (audit view)
GET    /sessions/active                live sessions (org)
GET    /sessions/{id}
POST   /sessions/{id}/terminate        force end (perm: session:terminate)
GET    /sessions/{id}/events           playback timeline
GET    /approvals?filter[status]=pending
POST   /approvals/{id}/approve
POST   /approvals/{id}/deny
```

### Recordings
```
GET    /recordings?filter[device]=&filter[user]=
GET    /recordings/{id}                metadata + artifact list
GET    /recordings/{id}/playback       signed, streamed playback URL
GET    /recordings/{id}/download       signed download (perm-gated, audited)
```

### Audit, dashboard, search, reports, notify
```
GET    /audit?action=&actor=&result=&from=&to=&limit=   log:read; newest-first
GET    /dashboard/summary              counts + top devices + recent activity
GET    /search?q=&limit=               global (users/devices/sessions)
POST   /reports    {type,format,from,to} -> CSV download   report:read
POST   /audit/verify?scope=&limit=              log:read; walks the hash chain
GET    /notification-channels  POST/PATCH/DELETE ...
```
`/audit/verify` recomputes the caller's organization chain and reports
`{ok, checked, from, to, unverifiable, truncated}`, plus `reason` and
`broken_at` when a link or a row fails. A super admin may pass `scope=system` for
the chain of events that belong to no tenant. `unverifiable` counts events
written before `hash_version` 2, whose hashes cannot be recomputed from what the
database stored; they are neither proved nor accused. A POST rather than a GET
because it is a full table walk.

`/reports` accepts `type: audit | access` and `format: csv` (default), returning
the CSV inline as an `attachment` download. `from`/`to` accept RFC 3339 or
`YYYY-MM-DD`. `/audit` and `/reports` are gated by `log:read` / `report:read`;
`/dashboard/summary` and `/search` require only authentication and are scoped to
the caller's organization by RLS (a super admin sees cross-tenant results).

### Organization settings
```
GET    /settings                         org:read; policy + your source address
GET    /settings/branding                any signed-in user (the console shell)
PUT    /settings/recording-retention  {days}                       org:write
PUT    /settings/branding  {client_name,client_logo,enabled}       org:write
PUT    /settings/network-policy  {allowlist_enabled,allowlist,
                                  blocklist_enabled,blocklist}     org:write
```
`/settings/branding` is readable by everybody because every page paints the
brand; the rest is an administrator's business. `client_logo` is a `data:` URI
under 400 000 characters, or `""`. Omitting `client_logo` from a PUT keeps the
stored artwork — saving a changed name must not silently discard the logo.

The network policy holds two independent lists of `{cidr, note}`, each with its
own switch, **both off by default**. The blocklist wins over the allowlist. A
policy that would refuse the address the request arrived from is rejected with
400 rather than stored; super admins are exempt from enforcement. Refusals are
audited as `auth.network_denied` and answered with 403.

### Ops (unauthenticated / infra)
```
GET    /healthz     liveness
GET    /readyz      readiness (db, redis, object store, migration ver)
GET    /metrics     Prometheus (bound to internal listener)
```

## Internal gRPC (API ↔ Gateway) — `gateway.v1`
```
rpc Establish(EstablishRequest) returns (EstablishResponse)   // start browser session
rpc ResolveCredential(ResolveRequest) returns (Credential)    // one-shot, JIT
rpc ReportEvent(SessionEvent) returns (Ack)                   // recording/timeline
rpc SessionEnded(EndRequest) returns (Ack)
rpc Terminate(TerminateRequest) returns (Ack)                 // fan-in from admin
```

## Versioning & deprecation
New breaking surface goes under `/api/v2`; `v1` stays until deprecation window
closes. Additive changes (new optional fields/endpoints) stay within `v1`.
OpenAPI diff is checked in CI to prevent accidental breaking changes.
