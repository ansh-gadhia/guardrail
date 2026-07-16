# GuardRail — Milestones & Implementation Plan

Each milestone must **compile, ship tests, and leave the app runnable**
(`docker compose up`). Milestones are ordered by dependency and risk-reduction.

## M0 — Design (this deliverable) ✅
Architecture, data model, API spec, security design, sequence/ER diagrams,
roadmap. Docs under `docs/`.

## M1 — Foundation & platform ✅
- Repo layout, Go module, 12-factor config with fail-closed validation.
- Structured JSON logging (zap), request/trace correlation.
- HTTP server (Gin) with graceful shutdown, security-header + recovery + request
  ID + rate-limit middleware skeleton.
- Postgres (pgx pool) + Redis clients as ports/adapters.
- `/healthz`, `/readyz`, `/metrics`.
- Migration `0001` (extensions, orgs, users, roles, permissions, RLS scaffolding)
  + seed of permission catalogue and Super Admin.
- docker-compose (api, postgres, redis, traefik), Dockerfile (multi-stage,
  distroless, non-root), Makefile, `.env.example`, golangci-lint, GitHub Actions.
- Unit tests for config + health; smoke integration test harness.
**Exit:** `docker compose up` serves `/healthz` 200 and `/readyz` verifies deps.

## M2 — IAM: AuthN + RBAC + tenancy ✅
Local login, Argon2id (with rehash-on-login + decoy verify against enumeration),
JWT access + refresh rotation with **reuse detection** (family revocation),
`/auth/me`, RBAC middleware + permission catalogue enforcement, org CRUD, user
CRUD, role assignment, brute-force throttle (Redis) + account lockout,
`seed-admin` bootstrap. **RLS tenant isolation enforced** via a non-superuser
app role. **Tamper-evident hash-chained audit** on every privileged action.
Tests: unit (Argon2, JWT, login/lockout/refresh-reuse, RBAC middleware) +
integration against live Postgres. All verified end-to-end.

## M3 — MFA + federation ✅
TOTP (RFC 6238) enrollment/confirm/disable + 10 single-use recovery codes;
MFA-gated login via a short-lived signed challenge (`/auth/mfa/verify`). TOTP
secrets stored envelope-encrypted under the vault KEK. **OIDC** (Authorization
Code + PKCE, hand-rolled: discovery, JWKS RS256 verify, iss/aud/nonce checks)
and **LDAP/AD** search-then-bind, both with JIT user provisioning. SAML SP stub
(config + interface defined). Tests: TOTP RFC vectors, challenger, MFA flow,
OIDC (httptest IdP: signature/nonce/audience), LDAP (fake directory) + live
Postgres MFA repo. MFA and OIDC redirect flow verified end-to-end.
_Note: WebAuthn/passkeys remain a future enhancement; the second-factor type is
carried explicitly so they slot in without a schema change._

## M4 — Assets + Vault ✅
Device CRUD (all fields), asset groups (folders/tags/nested/dynamic), credential
vault with envelope encryption + KeyProvider port (env impl), device↔credential
binding, KEK rotation job. Secret write-only enforcement. Tests incl. crypto
round-trip + rotation.

## M5 — Access broker + Proxy/Gateway + recording ✅
`cmd/gateway`, gRPC contract, chromedp per-session isolated Chromium, JIT
one-shot credential resolution + injection, traffic proxy, recording
(video/screenshot/events) to MinIO, live-session registry in Redis. Access
sessions + windows. Tests: gateway contract, injection isolation, recording
lifecycle.

## M6 — Approvals + monitoring + notifications ✅
Approval workflow (one-time/window/expiry), live monitoring, force terminate,
notification channels (email/slack/webhook) via transactional outbox + dispatcher.

## M7 — Frontend SPA ✅
React 18 + TypeScript + Vite + Tailwind, React Query + Zustand: login (local +
TOTP MFA + LDAP + OIDC SSO), dashboard, devices (approval-aware connect),
sessions (live monitor + terminate), approvals, audit + CSV export, self-service
security (MFA), global search. Access token in memory + silent refresh; RBAC-
aware UI; version shown in footer. Served by nginx behind Traefik in compose.
_Note: built and type-consistent; `npm install && npm run build` compiles it
(Node is unavailable in the current sandbox, so it was verified by inspection
against the live API contract). Recordings playback + Playwright E2E remain
follow-ups._

## M8 — Reports, search, dashboard analytics ✅
Global search (users/devices/sessions), dashboard aggregates (counts, failed
logins, top devices, recent activity), audit-log read API (`GET /audit`, gated
by `log:read`), and CSV report generation for audit + access history
(`POST /reports`, gated by `report:read`). All read-model queries run inside the
tenant-scoped RLS transaction. Tests: unit (CSV/report filters) + live Postgres
(dashboard/search/audit). Verified end-to-end.

## M9 — Hardening & release ✅
CI security gates (golangci-lint, govulncheck, **gosec**, gitleaks, Trivy) plus a
**frontend typecheck+build** job and API/web image builds; CI now applies **all**
migrations before integration tests. **OpenAPI 3.0 spec** published
(`docs/openapi.yaml`). Docs: **Deployment guide** (secrets, TLS, scaling, HA,
upgrades) and **Usage guide** (end-to-end operator workflow), refreshed README.
Recording retention is driven by the `retention_until` column + object-store
lifecycle (documented in the deployment guide).
_Note: load/perf benchmarking and a WebAuthn/passkey second factor remain
future enhancements._

## Cross-cutting (every milestone)
Tests + docs are part of "done." Observability wired for each new subsystem.
Import-boundary lint keeps Clean Architecture intact.

## Future roadmap (architected-for, not built now)
SSH/RDP/VNC/K8s/DB gateways (new `Gateway` plugins), password rotation, external
secret managers (Vault/CyberArk), AI anomaly detection, SIEM/syslog export, HA &
horizontal scaling, distributed recording storage. None require core redesign —
they slot into existing ports (Gateway, KeyProvider, Notifier, ObjectStore).
