# GuardRail

> Repository: **https://github.com/ansh-gadhia/guardrail**

> Secure Privileged Access Management (PAM) for **browser-based** access to
> network devices and security appliances — firewalls, routers, switches,
> wireless controllers, hypervisors, Windows and Linux hosts, and any HTTP/HTTPS
> admin interface.

Administrators click **Connect** and reach a device through an isolated,
recorded, fully-audited session in the browser. They never see or type the device
credentials — GuardRail injects them **server-side, just-in-time** and proxies
all traffic. RBAC, multi-tenancy, MFA, approvals, and tamper-evident audit are
built in.

GuardRail brokers, per device:

- **Web UIs** (`https`, `http`) — reverse proxy or server-side browser isolation
- **Terminals** (`ssh`, `telnet`) — server-side gateway; SSH keeps a text transcript
- **Desktops** (`rdp`, `vnc`) — rendered to the browser through the Apache **guacd** sidecar

Terminal and desktop protocols run behind the `desktop` Compose profile and are
off by default — see **[SETUP.md §5](SETUP.md#5-optional-enable-desktop--terminal-protocols-rdp-vnc-telnet-ssh)**.

**New here? Start with [SETUP.md](SETUP.md)** — prerequisites, architecture
diagram, the default port map, first sign-in, and troubleshooting.

## Status

Current version: **1.0.0** (see [`CHANGELOG.md`](CHANGELOG.md)).

| Milestone | Scope | State |
|---|---|---|
| M0 | Architecture, data model, API, security design, diagrams | ✅ |
| M1 | Foundation: config, logging, HTTP, DB/Redis, health, migrations, compose, CI | ✅ |
| M2 | IAM: local auth, Argon2id, JWT + refresh rotation, RBAC, tenancy, audit | ✅ |
| M3 | MFA (TOTP + recovery codes), OIDC (PKCE), LDAP/AD, SAML stub | ✅ |
| M4 | Assets + credential vault (envelope encryption) | ✅ |
| M5 | Access broker + credential-injecting proxy + recording | ✅ |
| M6 | Approvals, live monitoring, notifications (outbox) | ✅ |
| M7 | React + TypeScript web console | ✅ |
| M8 | Dashboard, global search, audit read API, CSV reports | ✅ |
| M9 | Hardening, OpenAPI, deployment & usage docs | ✅ |

## Documentation

- **[Setup guide](SETUP.md)** — prerequisites, architecture diagram, ports, first run
- **[Usage guide](docs/USAGE.md)** — the end-to-end operator workflow
- **[Deployment guide](docs/DEPLOYMENT.md)** — run it locally & in production
- [Architecture](docs/ARCHITECTURE.md) — Clean Architecture, bounded contexts, topology
- [Data model](docs/DATABASE.md) — ER diagram, tables, indexes, RLS
- [API design](docs/API.md) + [OpenAPI spec](docs/openapi.yaml)
- [Security](docs/SECURITY.md) — threat model, envelope encryption, OWASP mapping
- [Flows](docs/FLOWS.md) — auth, secure Connect, approvals, monitoring (Mermaid)
- [Roadmap](docs/ROADMAP.md) — milestones & future modules

## Quick start

Prerequisites: Docker + Docker Compose v2. (Node is needed only if you build the
console yourself; `make install` will tell you what is missing and stop.)

```bash
git clone https://github.com/ansh-gadhia/guardrail.git && cd guardrail
make install
```

That is the whole install. It generates `.env` with fresh secrets, issues a
self-signed certificate, starts Postgres and Redis, applies migrations, loads the
seed data, builds the console, and waits until the API answers `/healthz` — then
prints the console URL and the admin sign-in. It is idempotent: run it again
after a `git pull` to migrate and restart, and it will never overwrite an
existing `.env` (that file holds the vault master key — replacing it would orphan
every stored credential).

The first super admin is created on first boot from `GUARDRAIL_ADMIN_EMAIL` and
`GUARDRAIL_ADMIN_PASSWORD` in `.env`. Sign in and change the password from
**Account → Password**. To bootstrap manually instead, leave both blank and run
`docker compose exec api /guardrail seed-admin --email you@yourco.com --password '...'`.

If your devices are on a LAN the container network cannot reach — which is the
usual case for firewall and switch management UIs — run the API as a host process
instead:

```bash
make install-native
```

Verify the stack:

```bash
curl -fskS https://localhost/api/v1/version   # {"name":"GuardRail","version":"1.0.0"}
curl -fskS https://localhost/healthz          # ok
```

`-k` skips verification of the generated self-signed certificate; replace
`deploy/tls/*.pem` before real use ([Deployment §5.1](docs/DEPLOYMENT.md)). Ports
come from `.env` (`GUARDRAIL_HTTPS_PORT`, `GUARDRAIL_HTTP_PORT`, …).

Then follow the **[Usage guide](docs/USAGE.md)**: add a device → give it a
credential → **Connect**.

The full deployment story (TLS, secrets, scaling, HA, upgrades) is in the
**[Deployment guide](docs/DEPLOYMENT.md)**.

## What's in the box

- **Web console** (`frontend/`, React 18 + TS + Vite + Tailwind): login (local /
  MFA / LDAP / OIDC SSO), dashboard, devices, live sessions + desktop/terminal
  viewers, recording playback, approvals, audit + CSV export, self-service MFA,
  global search. App **version shown in the footer**.
- **API** (`backend/`, Go 1.26 + Gin): the full `/api/v1` surface, the
  credential-injecting proxy, background workers (notification dispatcher, session
  reaper, health poller), Prometheus metrics.
- **Session gateways**: reverse proxy + browser isolation (Chromium) for web UIs,
  an SSH/telnet gateway, and the Apache **guacd 1.5.5** sidecar for RDP/VNC/telnet
  desktops.
- **Edge**: Traefik v3.1 (TLS, HTTP→HTTPS redirect); nginx serves the SPA.
- **Data plane**: PostgreSQL 16 (with Row-Level Security), Redis 7.

See **[SETUP.md](SETUP.md)** for the architecture diagram and the default port map.

## Security-by-default highlights

- **Credentials never reach the user** — resolved just-in-time, held in memory,
  injected server-side by the proxy, and audited as `credential.use`.
- **Two-layer tenant isolation** — application `TenantScope` **and** PostgreSQL
  Row-Level Security; the API connects as a **non-superuser** role so RLS cannot
  be bypassed.
- **Append-only, hash-chained audit** — per-org SHA-256 chain; the app role has
  no `UPDATE`/`DELETE` on `audit_events`.
- **Strong auth** — Argon2id, JWT + rotating refresh tokens with **reuse
  detection**, brute-force throttle + lockout, **TOTP MFA** + recovery codes,
  OIDC (PKCE) and LDAP/AD federation.
- **Credential vault** — envelope encryption (AES-256-GCM DEK wrapped by a
  pluggable KEK provider) with KEK rotation; secrets are write-only over the API.
- **Fail-closed config** — refuses to start without strong secrets; rejects
  wildcard CORS and untrusted proxy headers in production.
- **Hardened runtime** — non-root image, static binary, strict
  security headers, Secure/HttpOnly/SameSite cookies.

See [`docs/SECURITY.md`](docs/SECURITY.md) for the full model and OWASP mapping.

## Developer workflow

```bash
# Backend
cd backend
make install           # fresh server -> running stack (idempotent)
make tidy              # go mod tidy (writes go.sum)
make run               # docker compose up --build
make migrate           # apply database migrations
make seed              # load the permission catalogue + system roles
make test              # unit tests (race, coverage)
make test-integration  # integration tests (-tags=integration; needs live Postgres)
make lint              # golangci-lint (enforces Clean-Architecture import rules)
make vuln              # govulncheck

# Frontend
cd frontend
npm install
npm run dev            # http://localhost:5173, proxies /api -> :8080
npm run build          # type-check (tsc) + production build
```

## Repository layout

```
guardrail/
├── SETUP.md                  # setup guide: prerequisites, architecture, ports
├── docs/                     # design + OpenAPI + usage/deployment guides
├── backend/
│   ├── cmd/guardrail/        # API entrypoint (composition root) + seed-admin
│   ├── internal/
│   │   ├── config/           # 12-factor config + validation
│   │   ├── platform/         # logger, httpserver, database, cache, metrics
│   │   ├── api/              # Gin router, middleware, v1 handlers
│   │   ├── domain/           # entities & ports: iam, assets, vault, access, audit, notify
│   │   ├── app/              # use cases per bounded context
│   │   └── infra/            # adapters: postgres, proxy, browser, sshgw, guacgw, federation, notify
│   ├── migrations/           # golang-migrate SQL (0001..0021)
│   ├── db/seed.sql           # permission catalogue, system roles, default org
│   └── test/                 # integration tests (-tags integration)
├── frontend/                 # React + TypeScript SPA (nginx-served)
├── deploy/
│   ├── postgres/init/        # app-role bootstrap for RLS
│   └── traefik/dynamic/      # Traefik routes + TLS config
├── scripts/                  # bootstrap.sh, install-deps.sh, run-host-api.sh
├── docker-compose.yml        # the whole stack: postgres, redis, guacd, migrate, seed, api, web, traefik
├── Makefile
├── .env.example
├── VERSION                   # single source of truth for the version
└── .github/workflows/ci.yml  # lint, test, frontend build, security scans, docker
```

## License

TBD (intended to resemble a production-ready open-source PAM platform).
