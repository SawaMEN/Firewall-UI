#!/usr/bin/env bash
set -Eeuo pipefail

REPO="SawaMEN/Firewall-UI"
RAW_BASE="https://raw.githubusercontent.com/${REPO}/main"
INSTALL_DIR="/usr/local/firewall-ui"
CONFIG_DIR="/etc/firewall-ui"
STATE_DIR="/var/lib/firewall-ui"
SERVICE_FILE="/etc/systemd/system/firewall-ui.service"
MANAGER="/usr/local/bin/firewall-ui"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd || true)"
TEMP_DIR=""
REPLACED=0
SUCCEEDED=0
HAD_BINARY=0
WAS_ACTIVE=0
WAS_ENABLED=0

pkg_install() {
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
  elif command -v dnf >/dev/null 2>&1; then dnf install -y "$@"
  elif command -v yum >/dev/null 2>&1; then yum install -y "$@"
  elif command -v pacman >/dev/null 2>&1; then pacman -S --needed --noconfirm "$@"
  elif command -v zypper >/dev/null 2>&1; then zypper --non-interactive install "$@"
  else echo 'A supported package manager (apt/dnf/yum/pacman/zypper) is required.' >&2; return 1; fi
}

detect_firewall() {
  local first="" backend binary
  for backend in ufw firewalld nftables iptables; do
    case "$backend" in ufw) binary=ufw;; firewalld) binary=firewall-cmd;; nftables) binary=nft;; iptables) binary=iptables;; esac
    command -v "$binary" >/dev/null 2>&1 || continue
    [[ -n "$first" ]] || first="$backend"
    case "$backend" in
      ufw) if LC_ALL=C ufw status 2>/dev/null | grep -qi '^Status: active'; then echo ufw; return; fi;;
      firewalld) if firewall-cmd --state 2>/dev/null | grep -qx running; then echo firewalld; return; fi;;
      nftables) if [[ -n "$(nft list ruleset 2>/dev/null)" ]]; then echo nftables; return; fi;;
      iptables) if iptables -S 2>/dev/null | grep -Eq '^-A |^-P .* (DROP|REJECT)$'; then echo iptables; return; fi;;
    esac
  done
  echo "${first:-none}"
}

check_system() {
  [[ "$(uname -s)" == Linux ]] || { echo 'Firewall-UI supports Linux only.' >&2; return 1; }
  case "$(uname -m)" in x86_64|amd64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; *) echo 'Unsupported CPU architecture.' >&2; return 1;; esac
  command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]] || { echo 'A running systemd is required.' >&2; return 1; }
  echo "Linux/$ARCH; detected firewall: $(detect_firewall)"
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 "$1" | awk '{print $NF}'
  else echo 'sha256sum or openssl is required.' >&2; return 1; fi
}

fetch_repo_file() {
  local path="$1" destination="$2"
  if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/$path" ]]; then
    install -m 0644 "$SCRIPT_DIR/$path" "$destination"
  else curl -fLsS --retry 3 --connect-timeout 15 "${RAW_BASE}/$path" -o "$destination"; fi
}

build_from_source() {
  command -v go >/dev/null && command -v npm >/dev/null && command -v tar >/dev/null || {
    echo 'No release is available. Wait for GitHub Actions, or supply FIREWALL_UI_BINARY from a local build.' >&2; return 1;
  }
  local directory="$TEMP_DIR/source"
  mkdir -p "$directory"
  curl -fLsS --retry 3 "https://github.com/${REPO}/archive/refs/heads/main.tar.gz" -o "$TEMP_DIR/source.tar.gz"
  tar -xzf "$TEMP_DIR/source.tar.gz" --strip-components=1 -C "$directory"
  (cd "$directory/frontend" && npm ci --ignore-scripts && npm run build)
  (cd "$directory" && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$TEMP_DIR/binary" ./cmd/firewall-ui)
}

download_binary() {
  if [[ -n "${FIREWALL_UI_BINARY:-}" ]]; then
    install -m 0755 "$FIREWALL_UI_BINARY" "$TEMP_DIR/binary"
    if [[ -n "${FIREWALL_UI_SHA256:-}" ]]; then
      [[ "$(sha256_file "$TEMP_DIR/binary")" == "$FIREWALL_UI_SHA256" ]] || { echo 'Local binary checksum mismatch.' >&2; return 1; }
    fi
    return
  fi
  local manifest_url channel block url expected actual
  channel="$UPDATE_CHANNEL"
  if [[ "$channel" == dev ]]; then manifest_url="https://github.com/${REPO}/releases/download/dev/update.json"
  else manifest_url="https://github.com/${REPO}/releases/latest/download/update.json"; fi
  if ! curl -fLsS --retry 3 --connect-timeout 15 "$manifest_url" -o "$TEMP_DIR/update.json"; then
    echo 'Release metadata is unavailable. Trying a local source build...'
    build_from_source
    return
  fi
  block="$(sed -n "/\"$ARCH\"[[:space:]]*:/,/^[[:space:]]*}/p" "$TEMP_DIR/update.json")"
  url="$(printf '%s\n' "$block" | sed -n 's/.*"url":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
  expected="$(printf '%s\n' "$block" | sed -n 's/.*"sha256":[[:space:]]*"\([0-9A-Fa-f]*\)".*/\1/p' | head -n 1)"
  [[ "$url" =~ ^https://github.com/${REPO}/releases/download/[A-Za-z0-9._-]+/firewall-ui-linux-${ARCH}$ && "$expected" =~ ^[0-9A-Fa-f]{64}$ ]] || {
    echo 'Invalid release metadata.' >&2; return 1;
  }
  if [[ -n "${FIREWALL_UI_DOWNLOAD_URL:-}" && "$FIREWALL_UI_DOWNLOAD_URL" != "$url" ]]; then
    echo 'Use FIREWALL_UI_BINARY and FIREWALL_UI_SHA256 for a custom binary; release downloads must match the manifest.' >&2; return 1
  fi
  curl -fLsS --retry 3 --connect-timeout 15 "$url" -o "$TEMP_DIR/binary"
  actual="$(sha256_file "$TEMP_DIR/binary")"
  [[ "${actual,,}" == "${expected,,}" ]] || { echo 'Release binary SHA-256 mismatch.' >&2; return 1; }
  chmod 0755 "$TEMP_DIR/binary"
}

escape_env_value() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

create_settings() {
  CONFIG_FILE="$CONFIG_DIR/config.json"
  if [[ ! -f "$CONFIG_FILE" ]]; then
    PANEL_PORT="${FIREWALL_UI_PORT:-8088}"
    PANEL_HOST="${FIREWALL_UI_LISTEN_HOST:-127.0.0.1}"
    [[ "$PANEL_PORT" =~ ^[0-9]{1,5}$ ]] && ((10#$PANEL_PORT>=1 && 10#$PANEL_PORT<=65535)) || { echo 'Invalid panel port.' >&2; return 1; }
    [[ "$PANEL_HOST" == localhost || "$PANEL_HOST" =~ ^[0-9a-fA-F:.]+$ ]] || { echo 'Invalid listen host.' >&2; return 1; }
    cat > "$CONFIG_FILE" <<JSON
{
  "listenHost": "$PANEL_HOST",
  "listenPort": $((10#$PANEL_PORT)),
  "externalPort": 0,
  "secureCookies": false,
  "statePath": "$STATE_DIR/state.json",
  "updateChannel": "$UPDATE_CHANNEL",
  "rollbackSeconds": 45,
  "portScanInterval": 2
}
JSON
    chmod 0600 "$CONFIG_FILE"
  fi
  # Read existing settings as well: repeat installs must never depend on creation-only variables.
  PANEL_HOST="$(sed -n 's/.*"listenHost":[[:space:]]*"\([^"]*\)".*/\1/p' "$CONFIG_FILE" | head -n 1)"
  PANEL_PORT="$(sed -n 's/.*"listenPort":[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$CONFIG_FILE" | head -n 1)"
  local env_file="$CONFIG_DIR/environment" username password
  if [[ ! -f "$env_file" ]]; then
    username="${FIREWALL_UI_USERNAME:-admin}"; password="${FIREWALL_UI_PASSWORD:-}"
    [[ -n "$username" && "$username" != *$'\n'* && "$username" != *$'\r'* ]] || { echo 'Invalid username.' >&2; return 1; }
    if [[ -z "$password" && "${FIREWALL_UI_NONINTERACTIVE:-0}" != 1 ]] && { exec 3<>/dev/tty; } 2>/dev/null; then
      read -r -s -p 'Firewall-UI password (12+ characters, Enter generates one): ' password <&3 || true
      printf '\n' >&3; exec 3>&-
    fi
    if [[ -z "$password" ]]; then password="$(od -An -N20 -tx1 /dev/urandom | tr -d ' \n')"; echo "Generated Firewall-UI password: $password"; fi
    [[ ${#password} -ge 12 && "$password" != *$'\n'* && "$password" != *$'\r'* ]] || { echo 'Password must contain at least 12 characters and no line breaks.' >&2; return 1; }
    local temp_env; temp_env="$(mktemp "$CONFIG_DIR/.environment-XXXXXX")"
    { printf 'FIREWALL_UI_USERNAME="%s"\n' "$(escape_env_value "$username")"; printf 'FIREWALL_UI_PASSWORD="%s"\n' "$(escape_env_value "$password")"; } > "$temp_env"
    chmod 0600 "$temp_env"; mv -f "$temp_env" "$env_file"
  fi
}

wait_for_service() {
  local i
  for i in {1..20}; do
    if systemctl is-active --quiet firewall-ui.service; then
      sleep 1
      systemctl is-active --quiet firewall-ui.service && return 0
    fi
    sleep .5
  done
  return 1
}

cleanup() {
  local result=$?
  if ((REPLACED && !SUCCEEDED)); then
    systemctl stop firewall-ui.service || true
    if ((!WAS_ENABLED)); then systemctl disable firewall-ui.service || true; fi
    echo 'Installation failed; restoring the previous service files.' >&2
    if ((HAD_BINARY)); then cp -p "$TEMP_DIR/previous-binary" "$INSTALL_DIR/firewall-ui"; else rm -f "$INSTALL_DIR/firewall-ui"; fi
    local name destination
    for name in manager service; do
      if [[ "$name" == manager ]]; then destination="$MANAGER"; else destination="$SERVICE_FILE"; fi
      if [[ -f "$TEMP_DIR/previous-$name" ]]; then cp -p "$TEMP_DIR/previous-$name" "$destination"; else rm -f "$destination"; fi
    done
    systemctl daemon-reload || true
    systemctl reset-failed firewall-ui.service || true
    if ((WAS_ACTIVE)); then systemctl restart firewall-ui.service || true; else systemctl stop firewall-ui.service || true; fi
  fi
  [[ -z "$TEMP_DIR" ]] || rm -rf -- "$TEMP_DIR"
  return "$result"
}

main() {
  case "${1:-}" in --help|-h) echo 'Usage: install.sh [--check]; FIREWALL_UI_NONINTERACTIVE=1 for unattended setup.'; return;; --check) check_system; return;; '') ;; *) echo 'Unknown option.' >&2; return 1;; esac
  [[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'Firewall-UI installer must run as root.' >&2; return 1; }
  check_system
  UPDATE_CHANNEL="${FIREWALL_UI_UPDATE_CHANNEL:-}"
  if [[ -z "$UPDATE_CHANNEL" && -f "$CONFIG_DIR/config.json" ]]; then UPDATE_CHANNEL="$(sed -n 's/.*"updateChannel":[[:space:]]*"\([^"]*\)".*/\1/p' "$CONFIG_DIR/config.json" | head -n 1)"; fi
  UPDATE_CHANNEL="${UPDATE_CHANNEL:-stable}"
  [[ "$UPDATE_CHANNEL" == stable || "$UPDATE_CHANNEL" == dev ]] || { echo 'Update channel must be stable or dev.' >&2; return 1; }
  command -v curl >/dev/null || pkg_install curl ca-certificates
  local backend; backend="$(detect_firewall)"
  if [[ "$backend" == none ]]; then echo 'No supported firewall found. Installing UFW...'; pkg_install ufw; command -v ufw >/dev/null || { echo 'UFW installation failed.' >&2; return 1; }; fi
  echo 'Existing firewall settings will be preserved. UFW is not enabled automatically.'
  TEMP_DIR="$(mktemp -d)"; trap cleanup EXIT
  download_binary
  fetch_repo_file deploy/firewall-ui "$TEMP_DIR/manager"
  fetch_repo_file deploy/firewall-ui.service "$TEMP_DIR/service"
  install -d -m 0755 "$INSTALL_DIR"
  install -d -m 0700 "$CONFIG_DIR" "$STATE_DIR"
  create_settings
  "$TEMP_DIR/binary" -config "$CONFIG_FILE" -check-config
  if [[ -f "$INSTALL_DIR/firewall-ui" ]]; then cp -p "$INSTALL_DIR/firewall-ui" "$TEMP_DIR/previous-binary"; HAD_BINARY=1; fi
  [[ ! -f "$MANAGER" ]] || cp -p "$MANAGER" "$TEMP_DIR/previous-manager"
  [[ ! -f "$SERVICE_FILE" ]] || cp -p "$SERVICE_FILE" "$TEMP_DIR/previous-service"
  systemctl is-active --quiet firewall-ui.service && WAS_ACTIVE=1
  systemctl is-enabled --quiet firewall-ui.service && WAS_ENABLED=1
  REPLACED=1
  install -m 0755 "$TEMP_DIR/binary" "$INSTALL_DIR/firewall-ui.new"; mv -f "$INSTALL_DIR/firewall-ui.new" "$INSTALL_DIR/firewall-ui"
  install -m 0755 "$TEMP_DIR/manager" "$MANAGER"
  install -m 0644 "$TEMP_DIR/service" "$SERVICE_FILE"
  systemctl daemon-reload
  systemctl enable firewall-ui.service
  systemctl reset-failed firewall-ui.service || true
  systemctl restart firewall-ui.service
  if ! wait_for_service; then systemctl status --no-pager firewall-ui.service || true; return 1; fi
  if ((HAD_BINARY)); then cp -p "$TEMP_DIR/previous-binary" "$INSTALL_DIR/firewall-ui.previous"; fi
  SUCCEEDED=1
  local host="$PANEL_HOST"
  [[ "$host" != *:* ]] || host="[$host]"
  [[ "$PANEL_HOST" != 0.0.0.0 && "$PANEL_HOST" != :: ]] || host='<server-ip>'
  [[ "$PANEL_HOST" != 0.0.0.0 && "$PANEL_HOST" != :: ]] || echo 'Public HTTP bind selected; configure TLS or an HTTPS reverse proxy in your deployment.'
  echo "Firewall-UI installed. Panel: http://${host}:${PANEL_PORT}/"
  echo 'Management: firewall-ui; logs: firewall-ui logs'
}
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
