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
FROM nginx:1.27-alpine AS runtime

# The console calls /api on its own origin, so it needs no build-time API URL and
# this one image serves whatever hostname or LAN address the server answers on.
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html

EXPOSE 80
