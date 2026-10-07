#!/usr/bin/env bash
set -euo pipefail

REPO="SawaMEN/Firewall-UI"
RAW_BASE="https://raw.githubusercontent.com/${REPO}/main"
INSTALL_DIR="/usr/local/firewall-ui"
CONFIG_DIR="/etc/firewall-ui"
STATE_DIR="/var/lib/firewall-ui"
SERVICE_FILE="/etc/systemd/system/firewall-ui.service"
MANAGER="/usr/local/bin/firewall-ui"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Firewall-UI installer must run as root."
  exit 1
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Firewall-UI supports Linux only."
  exit 1
fi

command -v systemctl >/dev/null 2>&1 || {
  echo "systemd is required by this installer."
  exit 1
}

pkg_install() {
  local package="$1"
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$package"
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y "$package"
  elif command -v yum >/dev/null 2>&1; then
    yum install -y "$package"
  elif command -v pacman >/dev/null 2>&1; then
    pacman -S --needed --noconfirm "$package"
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install "$package"
  elif command -v apk >/dev/null 2>&1; then
    apk add "$package"
  else
    echo "No supported package manager found."
    return 1
  fi
}

if ! command -v curl >/dev/null 2>&1; then
  echo "Installing curl..."
  pkg_install curl
fi

if ! command -v ufw >/dev/null 2>&1 &&
   ! command -v firewall-cmd >/dev/null 2>&1 &&
   ! command -v nft >/dev/null 2>&1 &&
   ! command -v iptables >/dev/null 2>&1; then
  echo "No supported firewall found. Installing UFW..."
  pkg_install ufw
fi

case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $(uname -m)"
    exit 1
    ;;
esac

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd || true)"

fetch_repo_file() {
  local path="$1" destination="$2"
  if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/$path" ]]; then
    install -m 0644 "$SCRIPT_DIR/$path" "$destination"
  else
    curl -fL --retry 3 --connect-timeout 15 "${RAW_BASE}/$path" -o "$destination"
  fi
}

install -d -m 0755 "$INSTALL_DIR"
install -d -m 0700 "$CONFIG_DIR" "$STATE_DIR"

TMP_BIN="$(mktemp)"
cleanup() {
  rm -f "$TMP_BIN"
}
trap cleanup EXIT

if [[ -n "${FIREWALL_UI_BINARY:-}" ]]; then
  install -m 0755 "$FIREWALL_UI_BINARY" "$TMP_BIN"
else
  DOWNLOAD_URL="${FIREWALL_UI_DOWNLOAD_URL:-https://github.com/${REPO}/releases/latest/download/firewall-ui-linux-${ARCH}}"
  echo "Downloading Firewall-UI for linux/${ARCH}..."
  if ! curl -fL --retry 3 --connect-timeout 15 "$DOWNLOAD_URL" -o "$TMP_BIN"; then
    echo "Release binary is unavailable. Trying a local source build..."
    if ! command -v go >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1 || ! command -v tar >/dev/null 2>&1; then
      echo "Install a published Firewall-UI release or install Go, Node.js/npm and tar, then run this installer again."
      exit 1
    fi
    BUILD_DIR="$(mktemp -d)"
    trap 'rm -f "$TMP_BIN"; rm -rf "$BUILD_DIR"' EXIT
    curl -fL --retry 3 "https://github.com/${REPO}/archive/refs/heads/main.tar.gz" -o "$BUILD_DIR/source.tar.gz"
    tar -xzf "$BUILD_DIR/source.tar.gz" -C "$BUILD_DIR"
    SOURCE_DIR="$(find "$BUILD_DIR" -maxdepth 1 -type d -name 'Firewall-UI-*' | head -n 1)"
    (
      cd "$SOURCE_DIR/frontend"
      npm ci --ignore-scripts
      npm run build
    )
    (
      cd "$SOURCE_DIR"
      CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$TMP_BIN" ./cmd/firewall-ui
    )
  fi
fi

install -m 0755 "$TMP_BIN" "$INSTALL_DIR/firewall-ui"

TMP_MANAGER="$(mktemp)"
TMP_SERVICE="$(mktemp)"
trap 'rm -f "$TMP_BIN" "$TMP_MANAGER" "$TMP_SERVICE"; [[ -n "${BUILD_DIR:-}" ]] && rm -rf "$BUILD_DIR"' EXIT
fetch_repo_file "deploy/firewall-ui" "$TMP_MANAGER"
fetch_repo_file "deploy/firewall-ui.service" "$TMP_SERVICE"
install -m 0755 "$TMP_MANAGER" "$MANAGER"
install -m 0644 "$TMP_SERVICE" "$SERVICE_FILE"

CONFIG_FILE="$CONFIG_DIR/config.json"
if [[ ! -f "$CONFIG_FILE" ]]; then
  PANEL_PORT="${FIREWALL_UI_PORT:-8088}"
  PANEL_HOST="${FIREWALL_UI_LISTEN_HOST:-127.0.0.1}"
  UPDATE_CHANNEL="${FIREWALL_UI_UPDATE_CHANNEL:-stable}"
  if [[ "$UPDATE_CHANNEL" != "stable" && "$UPDATE_CHANNEL" != "dev" ]]; then
    echo "FIREWALL_UI_UPDATE_CHANNEL must be stable or dev."
    exit 1
  fi
  cat > "$CONFIG_FILE" <<EOF
{
  "listenHost": "$PANEL_HOST",
  "listenPort": $PANEL_PORT,
  "externalPort": 0,
  "secureCookies": false,
  "statePath": "$STATE_DIR/state.json",
  "updateChannel": "$UPDATE_CHANNEL",
  "rollbackSeconds": 45,
  "portScanInterval": 2
}
EOF
  chmod 0600 "$CONFIG_FILE"
fi

escape_env_value() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

ENV_FILE="$CONFIG_DIR/environment"
if [[ ! -f "$ENV_FILE" ]]; then
  USERNAME="${FIREWALL_UI_USERNAME:-admin}"
  PASSWORD="${FIREWALL_UI_PASSWORD:-}"
  if [[ -z "$PASSWORD" ]]; then
    if [[ -r /dev/tty ]]; then
      while true; do
        read -r -s -p "Firewall-UI password (12+ characters): " PASSWORD < /dev/tty
        echo
        [[ ${#PASSWORD} -ge 12 ]] && break
        echo "Password is too short."
      done
    else
      PASSWORD="$(od -An -N18 -tx1 /dev/urandom | tr -d ' \n')"
      echo "Generated Firewall-UI password: $PASSWORD"
    fi
  fi
  if [[ ${#PASSWORD} -lt 12 ]]; then
    echo "FIREWALL_UI_PASSWORD must contain at least 12 characters."
    exit 1
  fi
  {
    printf 'FIREWALL_UI_USERNAME="%s"\n' "$(escape_env_value "$USERNAME")"
    printf 'FIREWALL_UI_PASSWORD="%s"\n' "$(escape_env_value "$PASSWORD")"
  } > "$ENV_FILE"
  chmod 0600 "$ENV_FILE"
fi

if [[ "$PANEL_HOST" == "0.0.0.0" || "$PANEL_HOST" == "::" ]]; then
  echo "WARNING: Firewall-UI will listen on all interfaces over HTTP unless you configure TLS/reverse proxy."
fi

systemctl daemon-reload
systemctl enable --now firewall-ui.service

PORT="$(sed -n 's/.*"listenPort":[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$CONFIG_FILE" | head -n 1)"
HOST="$(sed -n 's/.*"listenHost":[[:space:]]*"\([^"]*\)".*/\1/p' "$CONFIG_FILE" | head -n 1)"
[[ "$HOST" == "0.0.0.0" || "$HOST" == "::" ]] && HOST="<server-ip>"

echo
echo "Firewall-UI installed."
echo "Panel: http://${HOST:-127.0.0.1}:${PORT:-8088}/"
echo "Management: firewall-ui"
echo "Logs: firewall-ui logs"
