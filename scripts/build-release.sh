#!/usr/bin/env bash
set -euo pipefail
arch="${1:?architecture required}"
channel="${2:?channel required}"
version="${3:?version required}"
case "$arch" in amd64|arm64) ;; *) echo 'Unsupported architecture' >&2; exit 1 ;; esac
case "$channel" in dev|stable) ;; *) echo 'Unsupported channel' >&2; exit 1 ;; esac
build_time="${BUILD_TIME:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
commit="${BUILD_COMMIT:-${GITHUB_SHA:-$(git rev-parse HEAD)}}"
mkdir -p "dist-$channel"
GOOS=linux GOARCH="$arch" CGO_ENABLED=0 go build -trimpath \
  -ldflags="-s -w -X github.com/SawaMEN/Firewall-UI/internal/buildinfo.Version=$version -X github.com/SawaMEN/Firewall-UI/internal/buildinfo.Channel=$channel -X github.com/SawaMEN/Firewall-UI/internal/buildinfo.Commit=$commit -X github.com/SawaMEN/Firewall-UI/internal/buildinfo.BuildTime=$build_time" \
  -o "dist-$channel/firewall-ui-linux-$arch" ./cmd/firewall-ui
