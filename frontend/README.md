# GuardRail Web Console

React + TypeScript + Vite + Tailwind single-page app for GuardRail — the
Privileged Access Management console.

## Stack

- **React 18 + TypeScript**, routed with **react-router-dom**
- **@tanstack/react-query** for server state (caching, polling, invalidation)
- **zustand** for the auth session store (access token kept in memory only)
- **Tailwind CSS** for styling (dark-first)
- **Vite** dev server + build

## Features

- Login with local credentials, **TOTP MFA challenge**, LDAP (directory) tab,
  and an OIDC **SSO** button — driven by `GET /auth/providers`.
- **Dashboard**: device/session/user counts, failed-logins, top devices, recent
  activity.
- **Devices**: list + one-click **Connect** (handles approval-gated devices).
- **Sessions**: live active-session monitor (auto-refresh) + force terminate.
- **Approvals**: approve/deny pending access requests.
- **Audit Log**: filterable, tamper-evident event view + CSV export.
- **Security**: self-service TOTP enrollment, recovery codes, disable.
- **Global search** across users/devices/sessions.
- App **version** is shown in the sidebar footer, sourced live from
  `GET /api/v1/version` (single source of truth: the repo `VERSION` file).

## Develop

```bash
npm install
npm run dev          # http://localhost:5173, proxies /api -> http://localhost:8080
```

Point it at a running backend (`make run` in `../backend`, or `docker compose up`).

## Build

```bash
npm run build        # type-checks (tsc -b) then emits static assets to dist/
npm run preview      # serve the production build locally
```

## Container

The multi-stage `Dockerfile` builds the SPA and serves it with nginx, proxying
`/api` and `/proxy` to the `api` service (see the root `docker-compose.yml`).

## Auth model

The **access token lives only in memory** (never `localStorage`) to limit XSS
exposure; the **refresh token is an HttpOnly cookie** the browser sends
automatically. On a 401 the API client attempts a single silent refresh before
redirecting to the login screen.
