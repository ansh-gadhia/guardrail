# GuardRail — Security Design

Mapped to OWASP ASVS L2 and OWASP Top 10 (2021). "Secure by default, Zero Trust."

## Threat model (summary)
- **Assets protected:** device admin credentials, session recordings, audit
  trail, tenant isolation.
- **Primary adversaries:** malicious/curious insider, compromised operator
  account, tenant trying to reach another tenant, network attacker between
  GuardRail and devices.
- **Core guarantee:** an operator can *use* a device but never *learn* its
  credentials, and every privileged action is attributable and tamper-evident.

## Credential protection — envelope encryption
```
KEK (master, from env GUARDRAIL_MASTER_KEY or KMS/Vault provider)
 └─ wraps DEK (random 256-bit, one per credential)
      └─ AES-256-GCM encrypts the secret (nonce per encryption)
```
- Plaintext secrets exist only transiently in memory during inject; never
  logged, never persisted, never returned by any read API (write-only fields).
- KEK rotation re-wraps DEKs without touching ciphertext (`encryption_keys`
  registry, `kek_id` per credential). Provider is pluggable
  (`env` -> `kms` -> `hashicorp-vault` -> `cyberark`) behind a `KeyProvider` port.
- Crypto: `crypto/aes` + `cipher.NewGCM`, `crypto/rand` nonces, constant-time
  compares.

## Authentication
- Passwords hashed with **Argon2id** (tuned params, per-hash salt, versioned
  encoding for future re-tuning). bcrypt supported only for import.
- MFA: TOTP (RFC 6238), WebAuthn/passkeys, single-use recovery codes (hashed).
  MFA can be **enforced** per org / per role.
- Brute-force: Redis counters per (ip,email); exponential backoff; account
  lockout after N failures (`locked_until`); optional IP allowlists per org.
- Federation: LDAP/AD bind, OAuth2/OIDC code flow (PKCE). SAML port stubbed for
  future without core change.

## Session & token security
- Access JWT: 15 min, signed (EdDSA/HS depending on deploy), carries
  `perm_ver`; invalidated early if permissions change.
- Refresh: opaque, HttpOnly+Secure+SameSite=Strict cookie, **rotated每use**,
  reuse-detection revokes the whole family.
- Idle timeout + absolute session timeout + automatic logout; access-session
  windows are independently time-boxed (approval-driven).

## Web app hardening (edge + app)
- **Traefik/edge:** TLS (HSTS, `max-age` + preload), redirect http→https.
- **Security headers:** CSP (default-src 'self', no inline via nonces),
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Permissions-Policy` minimal,
  `Cross-Origin-Opener/Resource-Policy`.
- **CORS:** strict allowlist of the SPA origin; credentials mode explicit.
- **CSRF:** double-submit token for cookie-auth mutations.
- **Cookies:** Secure, HttpOnly, SameSite=Strict.

## Injection & input safety
- **SQL:** `pgx` with parameterized queries / prepared statements only; no string
  concatenation. `sqlc`-style typed queries.
- **XSS:** React auto-escaping + strict CSP; server never reflects raw input.
- **SSRF:** device connect targets are validated against the org's registered
  devices only; the Gateway resolves the target from the DB record, not from
  user-supplied URLs; egress from Gateway is allowlisted; link-local/metadata IP
  ranges blocked by default.
- **RCE/command injection:** no shell-outs with user input; browser automation
  uses the CDP API, not shell.
- **Deserialization:** strict JSON schema validation on every DTO
  (`go-playground/validator`), size limits, `DisallowUnknownFields`.

## AuthZ (RBAC + tenancy)
- Deny-by-default. Every route declares required permission(s); middleware
  enforces `permission ∈ principal.permissions` AND `resource.org == principal.org`.
- Permissions are granular per resource+action (e.g. `device:read`,
  `session:terminate`, `recording:download`, `approvals:decide`).
- Roles: Super Admin, Org Admin, Auditor, Operator, Read-only, plus custom.
- Tenant isolation defended twice: app-layer `TenantScope` + Postgres RLS.

## Audit — tamper-evident
- Append-only `audit_events`; DB role for the app has **no** UPDATE/DELETE on it.
- Per-org hash chain: `hash = SHA256(prev_hash || canonical(row))`; a verifier
  job detects any gap/mutation. Every entry carries the mandated fields
  (timestamp, user, org, ip, user agent, device, session id, result).
- Privileged actions (credential use, terminate, role change, approvals) always
  audited, even on failure/denial.

## Secrets & config
- No hardcoded secrets; all from env (Twelve-Factor) or secret provider.
- `.env.example` documents every variable; startup **fails closed** if a
  required secret is missing or weak (e.g. master key < 32 bytes).

## Supply chain & CI
- `govulncheck`, `gosec`, `trivy` (image + fs), `gitleaks`, dependency review in
  GitHub Actions; SBOM generated on release; pinned base images; non-root
  distroless runtime; read-only root FS; dropped capabilities.

## Data protection
- Recordings stored in object store with server-side encryption; access via
  short-lived signed URLs, permission-gated and audited. Retention policies
  auto-purge expired recordings and session events.

## OWASP Top 10 coverage matrix
| Risk | Control |
|---|---|
| A01 Broken Access Control | deny-by-default RBAC + RLS + tenant guard, per-route perms |
| A02 Cryptographic Failures | envelope AES-256-GCM, Argon2id, TLS everywhere |
| A03 Injection | parameterized SQL, CDP (no shell), strict validation, CSP |
| A04 Insecure Design | threat model, approval workflow, least privilege, this doc |
| A05 Misconfiguration | secure headers, fail-closed config, hardened images |
| A06 Vulnerable Components | govulncheck/trivy/dependency review, pinned deps |
| A07 Auth Failures | Argon2id, MFA, lockout, rotation, reuse detection |
| A08 Integrity Failures | signed images, SBOM, hash-chained audit |
| A09 Logging/Monitoring | structured logs, OTel, Prometheus, audit trail |
| A10 SSRF | device-record-only targets, egress allowlist, blocked metadata IPs |
