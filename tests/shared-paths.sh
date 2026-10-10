#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIXTURE="$(mktemp -d)"
trap 'rm -rf -- "$FIXTURE"' EXIT
source "$ROOT/deploy/firewall-ui-docker"
DOCKER_DIR="$FIXTURE/new"
DOCKER_CONFIG_DIR="$FIXTURE/config"
DOCKER_STATE_DIR="$FIXTURE/state"
LEGACY_DOCKER_DIR="$FIXTURE/old"
mkdir -p "$LEGACY_DOCKER_DIR/source" "$LEGACY_DOCKER_DIR/access/tls/test" "$LEGACY_DOCKER_DIR/access/state"
mkdir -p "$FIXTURE/volume-config" "$FIXTURE/volume-data"
echo managed > "$LEGACY_DOCKER_DIR/.installer-managed"
echo host > "$LEGACY_DOCKER_DIR/deployment"
echo admin > "$LEGACY_DOCKER_DIR/username"
echo password > "$LEGACY_DOCKER_DIR/password"
echo old-compose > "$LEGACY_DOCKER_DIR/source/compose.yaml"
echo cert > "$LEGACY_DOCKER_DIR/access/tls/test/fullchain.pem"
echo key > "$LEGACY_DOCKER_DIR/access/tls/test/privkey.pem"
echo 8088 > "$LEGACY_DOCKER_DIR/access/state/access-ufw"
printf 'FIREWALL_UI_TLS_CERT=%s/access/tls/test/fullchain.pem\n' "$LEGACY_DOCKER_DIR" > "$LEGACY_DOCKER_DIR/docker.env"
printf '{"tlsCert":"%s/access/tls/test/fullchain.pem","updateChannel":"dev"}\n' "$LEGACY_DOCKER_DIR" > "$FIXTURE/volume-config/config.json"
echo credentials > "$FIXTURE/volume-config/environment"
echo state > "$FIXTURE/volume-data/state.json"
docker_owned_volumes() { printf 'config-volume\ndata-volume\n'; }
docker_owned_containers() { echo panel; }
docker() {
  if [[ "$1 $2" == "volume inspect" ]]; then
    local last
    for last; do :; done
    case "$*" in
      *Mountpoint*)
        case "$last" in
          config-volume) echo "$FIXTURE/volume-config";;
          data-volume) echo "$FIXTURE/volume-data";;
        esac;;
      *)
        case "$last" in
          config-volume) echo firewall-ui-config;;
          data-volume) echo firewall-ui-data;;
        esac;;
    esac
  elif [[ "$1" == stop ]]; then local last; for last; do :; done; echo "$last" >> "$FIXTURE/stops"
  else return 1; fi
}
docker_migrate_legacy_layout
[[ "$DOCKER_MIGRATED" == 1 ]]
[[ -f "$DOCKER_CONFIG_DIR/environment" && -f "$DOCKER_STATE_DIR/state.json" ]]
[[ -f "$DOCKER_CONFIG_DIR/tls/test/privkey.pem" && -f "$DOCKER_STATE_DIR/access-ufw" ]]
grep -Fq "$DOCKER_CONFIG_DIR/tls/test/fullchain.pem" "$DOCKER_CONFIG_DIR/config.json"
grep -Fq "$DOCKER_CONFIG_DIR/tls/test/fullchain.pem" "$DOCKER_DIR/docker.env"
[[ "$(docker_update_channel)" == dev ]]
[[ -f "$LEGACY_DOCKER_DIR/.installer-managed" && -f "$FIXTURE/volume-config/config.json" ]]
[[ "$(cat "$FIXTURE/stops")" == panel ]]
# Existing unrelated data must block migration without stopping or overwriting.
rm -rf -- "$DOCKER_DIR"
echo unrelated > "$DOCKER_CONFIG_DIR/unrelated"
if docker_migrate_legacy_layout; then echo 'Migration overwrote another installation' >&2; exit 1; fi
grep -qx unrelated "$DOCKER_CONFIG_DIR/unrelated"

# Switching native to Docker keeps the shared config and imports external PEM.
source "$ROOT/install.sh"
source "$ROOT/deploy/firewall-ui-switch"
CONFIG_DIR="$FIXTURE/native-config"
STATE_DIR="$FIXTURE/native-state"
INSTALL_DIR="$FIXTURE/native-install"
SERVICE_FILE="$FIXTURE/native.service"
MANAGER="$FIXTURE/native-manager"
export FIREWALL_UI_DOCKER_DIR="$FIXTURE/new-variant" FIREWALL_UI_DOCKER_MANAGER="$FIXTURE/docker-manager"
mkdir -p "$CONFIG_DIR" "$STATE_DIR" "$INSTALL_DIR" "$FIXTURE/external"
printf 'cert\n' > "$FIXTURE/external/fullchain.pem"
printf 'key\n' > "$FIXTURE/external/privkey.pem"
printf '{"listenHost":"127.0.0.1","listenPort":8443,"publicHost":"demo.example.org","tlsCert":"%s","tlsKey":"%s","updateChannel":"dev"}\n' \
  "$FIXTURE/external/fullchain.pem" "$FIXTURE/external/privkey.pem" > "$CONFIG_DIR/config.json"
printf 'FIREWALL_UI_USERNAME="admin"\nFIREWALL_UI_PASSWORD="password"\n' > "$CONFIG_DIR/environment"
echo state > "$STATE_DIR/state.json"
echo native > "$MANAGER"
echo unit > "$SERVICE_FILE"
systemctl() { return 0; }
run_installer_docker_action() {
  mkdir -p "$FIREWALL_UI_DOCKER_DIR"
  printf 'host\n' > "$FIREWALL_UI_DOCKER_DIR/deployment"
  printf '%s\n' \
    'FIREWALL_UI_DOCKER_HOST=127.0.0.1' 'FIREWALL_UI_DOCKER_PORT=8088' \
    'FIREWALL_UI_DOCKER_PORTS=0' 'FIREWALL_UI_PUBLIC_HOST=' \
    'FIREWALL_UI_TLS_CERT=' 'FIREWALL_UI_TLS_KEY=' \
    'FIREWALL_UI_TLS_MODE=' 'FIREWALL_UI_OPEN_PORTS=0' > "$FIREWALL_UI_DOCKER_DIR/docker.env"
  cat > "$FIREWALL_UI_DOCKER_MANAGER" <<'MOCK'
docker_compose() { return 0; }
docker_wait_for_service() { return 0; }
docker_setup_updates() { return 0; }
docker_setup_renewal() { return 0; }
docker_update_status() { return 0; }
MOCK
}
switch_remove_native() { rm -rf -- "$INSTALL_DIR"; rm -f -- "$SERVICE_FILE"; }
switch_native_to_docker
[[ ! -d "$INSTALL_DIR" && ! -e "$SERVICE_FILE" ]]
[[ -f "$CONFIG_DIR/environment" && -f "$STATE_DIR/state.json" ]]
grep -Fq "$CONFIG_DIR/tls/import-" "$CONFIG_DIR/config.json"
grep -Fq "$CONFIG_DIR/tls/import-" "$FIREWALL_UI_DOCKER_DIR/docker.env"
grep -qx 'FIREWALL_UI_DOCKER_PORT=8443' "$FIREWALL_UI_DOCKER_DIR/docker.env"

echo 'Legacy Docker metadata, shared TLS/state and dev channel migration and native-to-Docker switching verified'
