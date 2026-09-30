# syntax=docker/dockerfile:1

# 1) Build the Svelte UI -> internal/ui/dist
FROM node:22-slim AS ui
WORKDIR /src/web
COPY web/package.json web/package-lock.json* ./
RUN npm install --no-audit --no-fund
COPY web/ ./
RUN npm run build   # writes to /src/internal/ui/dist

# 2) Build the Go binary with the UI embedded
FROM golang:1.25-alpine AS backend
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /src/internal/ui/dist ./internal/ui/dist
ARG BUILD_VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags="-s -w -X github.com/yundera/auth-console/internal/server.Version=${BUILD_VERSION}" \
      -o /auth-console ./cmd/auth-console

# 3) Runtime. The same image is also the host-verb runner (internal/dockerx
#    RunOnHost), which is the only reason nsenter is here: util-linux-misc
#    provides it. ca-certificates for the operator support-key call and the
#    SSH public-key deep-link fetch.
FROM alpine:3.22
RUN apk add --no-cache ca-certificates util-linux-misc
COPY --from=backend /auth-console /auth-console
EXPOSE 8080
ENTRYPOINT ["/auth-console"]
