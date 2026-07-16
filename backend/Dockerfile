# syntax=docker/dockerfile:1.7

# --- build stage -----------------------------------------------------------
# Must satisfy the `go` directive in go.mod (currently 1.26). GOTOOLCHAIN=local
# in the base image means a lower tag fails the build outright rather than
# quietly fetching a newer toolchain.
FROM golang:1.26-alpine AS build
WORKDIR /src

# Cache dependencies first for faster incremental builds.
COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .
ARG VERSION=dev
# CGO disabled -> fully static binary; trimpath + ldflags shrink the image and
# strip local paths. Build the API entrypoint.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build \
    -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/guardrail ./cmd/guardrail

# --- runtime stage ---------------------------------------------------------
# Debian slim rather than distroless, because browser isolation runs a real
# Chromium per session. Without it the isolation gateway cannot start and every
# recording-enabled device silently falls back to the reverse proxy, which sees
# no pixels — so recording policy would be off while still reading as "on".
#
# fonts-liberation is not optional: Chromium with no fonts renders device UIs
# and the session watermark as blank boxes, and the watermark is an audit control.
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        chromium \
        ca-certificates \
        fonts-liberation \
        tini \
    && rm -rf /var/lib/apt/lists/*

# Chromium orphans zombie renderers when PID 1 doesn't reap; tini does.
ENTRYPOINT ["/usr/bin/tini", "--", "/guardrail"]

COPY --from=build /out/guardrail /guardrail

ENV GUARDRAIL_CHROME_PATH=/usr/bin/chromium \
    GUARDRAIL_RECORDING_DIR=/var/lib/guardrail/recordings

# Unprivileged: Chromium is launched with --no-sandbox (see internal/infra/browser),
# so it needs no extra capabilities, and nothing here should run as root.
#
# The recording handover to guacd does NOT depend on this user's gid: compose adds
# guacd's group (gid 1000) to this process as a supplementary group, so it reads
# guacd's group-readable recordings whatever its own primary gid is. That is
# deliberately more robust than matching gids across two images — it turns on one
# well-known number (guacd's 1000) instead of a fragile agreement about this one.
RUN useradd --system --uid 65532 --create-home --home-dir /home/guardrail guardrail \
    && mkdir -p /var/lib/guardrail/recordings \
    && chown -R guardrail:guardrail /var/lib/guardrail
USER guardrail:guardrail

EXPOSE 8080 9090
