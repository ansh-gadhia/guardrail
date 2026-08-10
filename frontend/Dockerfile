# syntax=docker/dockerfile:1.7

# --- build stage -----------------------------------------------------------
FROM node:20-alpine AS build
WORKDIR /src

# Dependencies first, so a source-only change doesn't refetch the tree.
COPY package.json package-lock.json* ./
RUN npm ci

COPY . .
# `npm run build` runs tsc --noEmit ahead of vite build, so a type error fails
# the image instead of shipping a broken console.
RUN npm run build

# --- runtime stage ---------------------------------------------------------
#
# The unprivileged nginx image, not the stock one: it runs as uid 101 instead of
# root and listens on 8080, because a container that does not need root should
# not have it. A console that brokers privileged access is a poor place to leave
# a root process serving static files — a compromise there starts one step from a
# container escape rather than several.
#
# The port change is the visible cost: nginx cannot bind 80 as a normal user, so
# the upstream in deploy/traefik/dynamic/routes.yml points at 8080. Nothing is
# published on the host either way; Traefik is the only thing that reaches it.
FROM nginxinc/nginx-unprivileged:1.27-alpine AS runtime

# The console calls /api on its own origin, so it needs no build-time API URL and
# this one image serves whatever hostname or LAN address the server answers on.
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html

# Restated even though the base image already sets it. Two reasons: a static
# scanner reads this file, not the base image's history, so an implicit user
# looks identical to root; and a future base-image bump that quietly dropped it
# would otherwise go unnoticed.
USER 101

EXPOSE 8080
