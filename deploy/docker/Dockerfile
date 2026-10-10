# syntax=docker/dockerfile:1
FROM node:24-alpine AS frontend
WORKDIR /src/frontend
COPY frontend/package*.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --ignore-scripts
COPY frontend/ ./
RUN npm run build

FROM golang:1.25-alpine AS backend
WORKDIR /src
COPY go.mod ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY VERSION ./VERSION
COPY --from=frontend /src/internal/webassets/dist/ ./internal/webassets/dist/
ARG TARGETARCH
ARG VCS_REF=unknown
ARG BUILD_CHANNEL=stable
RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags="-s -w -X github.com/SawaMEN/Firewall-UI/internal/buildinfo.Version=$(if [ \"${BUILD_CHANNEL}\" = dev ]; then echo dev-$(printf \"%s\" \"${VCS_REF}\" | cut -c1-7); else cat VERSION; fi) -X github.com/SawaMEN/Firewall-UI/internal/buildinfo.Channel=${BUILD_CHANNEL} -X github.com/SawaMEN/Firewall-UI/internal/buildinfo.Commit=${VCS_REF}" \
    -o /out/firewall-ui ./cmd/firewall-ui

FROM alpine:3.22
RUN apk add --no-cache ca-certificates nftables iptables docker-cli util-linux \
    && mkdir -p /etc/firewall-ui \
    && chmod 700 /etc/firewall-ui
COPY --from=backend /out/firewall-ui /usr/local/bin/firewall-ui
COPY deploy/docker/entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 755 /usr/local/bin/docker-entrypoint.sh
ENV FIREWALL_UI_CONTAINER=1
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD []
