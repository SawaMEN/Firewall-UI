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
echo 'Legacy Docker metadata, shared TLS/state and dev channel migration verified'
