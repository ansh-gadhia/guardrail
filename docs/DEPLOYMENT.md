# GuardRail — Deployment Guide

This guide covers running GuardRail locally and deploying it to a server. The
stack is container-first and lives in **one `docker-compose.yml`**: **PostgreSQL
16, Redis 7, the Go API (with Chromium, for isolated/recorded sessions), the
React web console (nginx), and Traefik (edge/TLS)**.

Recordings are written to a **local volume** (`GUARDRAIL_RECORDING_DIR`), not an
object store.

---

## 1. Prerequisites

- Docker + Docker Compose v2 (`docker compose version`)
- A domain name and DNS record pointing at the host (for TLS in production)
- ~2 vCPU / 2 GB RAM to start; scale the API horizontally as load grows

For local development without Docker you also need Go 1.23+ and Node 20+.

---

## 2. Configure secrets (`.env`)

Copy the template and fill in **strong, unique** secrets. The API **fails to
start** if any required secret is missing or shorter than 32 bytes.

```bash
cp .env.example .env
# Generate strong values:
openssl rand -base64 48   # use for each *_KEY / password below
```

Required:

| Variable | Purpose |
|---|---|
| `POSTGRES_PASSWORD` | Postgres superuser (migrations only) |
| `GUARDRAIL_DB_APP_PASSWORD` | Least-privilege app login role (RLS enforced) |
| `GUARDRAIL_JWT_SIGNING_KEY` | Signs access tokens (≥ 32 bytes) |
| `GUARDRAIL_MASTER_KEY` | KEK for the credential vault (≥ 32 bytes) |

> **Rotate `GUARDRAIL_MASTER_KEY` carefully.** It wraps every credential DEK.
> The vault supports KEK rotation (re-wrap) without re-encrypting secrets; do not
> simply change the value without running a rotation.

Optional federation (leave blank to disable): `GUARDRAIL_FEDERATION_ORG_ID` plus
the `GUARDRAIL_OIDC_*` and/or `GUARDRAIL_LDAP_*` variables (see `.env.example`).

---

## 3. Bring up the stack

```bash
docker compose up -d --build
```

Order is handled for you: Postgres/Redis become healthy → the `migrate` service
applies all migrations → the API starts → the web console and Traefik come up.

Check health:

```bash
docker compose ps
curl -fskS https://localhost/api/v1/version   # {"name":"GuardRail","version":"…"}
curl -fskS https://localhost/healthz          # ok
```

Open the console at **https://localhost/** — or, from any other PC on the
network, **https://\<server-lan-ip\>/**. Nothing needs rebuilding for a different
address: the console calls the API on whatever origin it was loaded from.

`-k` is needed above only because the bundled certificate is self-signed; see
§5.1 to replace it.

### What each service does

| Service | Role |
|---|---|
| `postgres` | System of record; **Row-Level Security** enforces tenant isolation |
| `redis` | Brute-force throttle, live-session registry, cross-node signals |
| `migrate` | One-shot; applies `backend/migrations/*.up.sql`, then exits |
| `seed` | One-shot; loads the permission catalogue, system roles, default org |
| `api` | Go API; connects as the **non-superuser** `guardrail_app` role. Ships Chromium for isolated/recorded sessions |
| `web` | React SPA served by nginx |
| `traefik` | Edge router (`/api`, `/proxy`, `/healthz` → api; everything else → web); terminates TLS |

Traefik's routes and TLS are declared in `deploy/traefik/dynamic/*.yml`, not
discovered from container labels. That keeps `/var/run/docker.sock` — access to
which is equivalent to root on the host — out of the most exposed container in
the stack, and avoids Traefik's Docker client pinning an API version that Docker
Engine 25+ rejects. Edit those files if you add a service.

### Ports

Every published port comes from `.env`; nothing is hardcoded in the compose file.

| Variable | Default | Exposure | Purpose |
|---|---|---|---|
| `GUARDRAIL_HTTPS_PORT` | `443` | LAN | Console, API and brokered sessions |
| `GUARDRAIL_HTTP_PORT` | `80` | LAN | Redirects to HTTPS; serves nothing |
| `POSTGRES_PORT` | `5432` | `127.0.0.1` | psql, backups |
| `REDIS_PORT` | `6379` | `127.0.0.1` | redis-cli |

The API (`8080`) and its metrics (`9090`) are **not published**; they stay on the
internal Docker network behind Traefik.

Postgres and Redis bind to `POSTGRES_BIND_ADDR` / `REDIS_BIND_ADDR`, both
`127.0.0.1` by default. Setting either to `0.0.0.0` puts your credential vault and
audit trail on the network — don't, unless you mean it.

Traefik listens on the same port inside the container as the one published on the
host, so the HTTP→HTTPS redirect points at a port that is actually listening.
Keep that symmetry if you edit the compose file by hand.

### Persistence and restarts

State lives in named volumes — `pgdata`, `redisdata`, `recordings` — which
survive `docker compose down`, `up`, rebuilds and reboots. Only `docker compose
down -v` destroys them.

Every service is `restart: unless-stopped`, so the stack returns by itself after a
reboot **provided the Docker daemon starts at boot**:

```bash
sudo systemctl enable docker
```

### Moving to another server

Copy the folder (including `.env`), then `docker compose up -d --build`. The
named volumes do **not** travel with the folder — migrate them explicitly:

```bash
# on the old server
docker compose exec -T postgres pg_dump -U guardrail guardrail | gzip > guardrail.sql.gz
docker run --rm -v guardrail_recordings:/d -v "$PWD":/b alpine \
  tar czf /b/recordings.tar.gz -C /d .

# on the new one, after `docker compose up -d postgres`
gunzip -c guardrail.sql.gz | docker compose exec -T postgres psql -U guardrail -d guardrail
docker run --rm -v guardrail_recordings:/d -v "$PWD":/b alpine \
  tar xzf /b/recordings.tar.gz -C /d
```

Restore recordings **and** the database together: a recording without its session
row is unreachable, and a session row promising video that isn't there reads as
tampering during an audit.

---

## 4. Bootstrap the first admin

The seed data creates the permission catalogue, system roles, and a default
organization, but **no user** (password hashing lives in app code). Create the
super admin:

```bash
docker compose exec api /guardrail seed-admin \
  --email admin@yourco.com --password 'a-strong-password-min-12-chars'
```

Sign in at the console with those credentials.

---

## 5. Production hardening

### 5.1 TLS

HTTPS is on by default — Traefik terminates it and the HTTP port only redirects.
What ships is a **self-signed** certificate, so browsers warn until you replace it.
Pick one:

**Your own certificate (LAN, internal CA).** Overwrite the PEMs and restart:

```bash
cp your-cert.pem deploy/tls/cert.pem
cp your-key.pem  deploy/tls/key.pem
docker compose restart traefik
```

**Regenerate the self-signed one for this server's address.** The SAN must list
the address operators actually type, or the browser rejects it regardless:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
  -subj "/CN=GuardRail/O=GuardRail" \
  -addext "subjectAltName=IP:192.168.1.50,IP:127.0.0.1,DNS:localhost" \
  -keyout deploy/tls/key.pem -out deploy/tls/cert.pem
docker compose restart traefik
```

**A public domain (Let's Encrypt).** Needs a real DNS name and inbound `:80`
from the internet — it will not work for a LAN-only address. Add to the `traefik`
command:

```
--certificatesresolvers.le.acme.email=ops@yourco.com
--certificatesresolvers.le.acme.storage=/acme.json
--certificatesresolvers.le.acme.tlschallenge=true
```

then give each router in `deploy/traefik/dynamic/routes.yml` a `certResolver`
and the hostname it should be issued for:

```yaml
tls:
  certResolver: le
  domains:
    - main: "guardrail.yourco.com"
```

Self-signed still encrypts the session, but it cannot prove the server is yours: a
click-through warning is exactly what a machine-in-the-middle looks like. On a
network where that matters, use an internal CA your machines already trust.

Also set `GUARDRAIL_ENV=production` so cookies are marked `Secure`.

### 5.2 Everything else

2. **CORS.** Leave `GUARDRAIL_CORS_ALLOW_ORIGINS` empty under compose — the
   console and API share an origin. Only set it (to exact origins) if you host
   the console separately. Production refuses the wildcard.
3. **Proxy trust.** Keep `GUARDRAIL_TRUST_PROXY_HEADERS=true` **only** behind
   Traefik, and set `GUARDRAIL_TRUSTED_PROXIES` to the proxy's CIDR (not
   `0.0.0.0/0`) so client IPs in the audit log are trustworthy.
4. **Secrets management.** In real deployments inject secrets from your platform
   (Kubernetes Secrets, Vault, SSM) rather than a committed `.env`.
5. **Database.** Use a managed Postgres or a replicated cluster; keep the
   `guardrail_app` role non-superuser so RLS cannot be bypassed. Take regular
   base backups + WAL archiving.
6. **Recordings.** The `recordings` volume holds session video and grows without
   bound. Put it on durable storage, back it up with the database, and set a
   retention policy (`retention_until`) per your compliance needs.
7. **Datastore exposure.** Keep `POSTGRES_BIND_ADDR` / `REDIS_BIND_ADDR` on
   `127.0.0.1`. Postgres holds the credential vault and the audit trail.

---

## 6. Scaling & HA

- The **API is stateless** — run N replicas behind Traefik. All shared state is
  in Postgres (durable) and Redis (throttle, live-session registry with
  cross-node terminate signalling), so any replica can serve any request.
- Run **Postgres** with a primary + replica and automatic failover.
- Run **Redis** with Sentinel or a managed equivalent.
- Background workers (notification dispatcher, session reaper) run in-process on
  every replica; they use advisory locks / atomic SQL so duplicate runs are safe.

---

## 7. Upgrades

1. Pull the new images / rebuild: `docker compose build`.
2. `docker compose up -d migrate` applies new migrations (idempotent, ordered).
3. `docker compose up -d api web` performs a rolling restart.

The running version is always visible at `GET /api/v1/version` and in the console
footer; the single source of truth is the repo `VERSION` file, injected at build
time. See `CHANGELOG.md` for what changed.

---

## 8. Troubleshooting

**Sessions time out reaching a device on the LAN, but the server can ping it.**
Check whether Docker is running **rootless** (`docker info | grep -i rootless`).
Rootless Docker's network namespace often cannot reach private LAN addresses, and
GuardRail's whole job is proxying LAN management UIs — so the API container may
be unable to reach a device the host reaches fine. Either run a normal root
Docker daemon, or run the API as a host process (`scripts/run-host-api.sh`)
pointed at the containerised datastores via `POSTGRES_BIND_ADDR`.

**Recording is enabled on a device but produces no video.** Recording requires
browser isolation (`GUARDRAIL_BROWSER_ISOLATION=true`, the default) *and* a
Chromium binary. The bundled API image ships one; if you build a custom image,
set `GUARDRAIL_CHROME_PATH`. Without it the session silently falls back to the
reverse proxy, which never sees pixels. `GET /api/v1/capabilities` reports
whether the server can record at all.

**Browser warns about the certificate.** Expected until you replace the bundled
self-signed cert — see §5.1.

**`docker compose up --build` fails on the API image.** The build stage must
satisfy the `go` directive in `backend/go.mod`; bump the `golang:` tag in
`backend/Dockerfile` if you raise it.

---

## 9. Local development (no containers)

```bash
# Terminal 1 — backend
cd backend
export $(grep -v '^#' ../.env | xargs)   # or set the GUARDRAIL_* vars
make migrate && make run                  # serves :8080

# Terminal 2 — frontend
cd frontend
npm install && npm run dev                # serves :5173, proxies /api -> :8080
```

Run the tests:

```bash
cd backend
make test                                  # unit
GUARDRAIL_TEST_DSN=postgres://guardrail_app:...@localhost:5432/guardrail?sslmode=disable \
  go test -tags integration ./test/...     # integration (needs live Postgres)
```
