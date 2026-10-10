#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE="$(mktemp -d)"
trap 'rm -rf -- "$FIXTURE"' EXIT
source "$ROOT/install.sh"
source "$ROOT/deploy/firewall-ui-switch"

INSTALL_INTERACTIVE=1
switch_native_to_docker() { echo 'to-docker' >> "$FIXTURE/switched"; }
switch_docker_to_native() { echo 'to-native' >> "$FIXTURE/switched"; }

# A rejected replacement must not touch either installation.
printf 'n\n' > "$FIXTURE/answer"
exec 3< "$FIXTURE/answer"
installer_switch_variant docker > "$FIXTURE/prompt"
[[ "$(cat "$FIXTURE/prompt")" == *'Удалить обычную версию и установить Docker'* ]]
[[ ! -e "$FIXTURE/switched" ]]

# Confirm both directions. No new credentials should be requested by the prompt.
printf 'y\n' > "$FIXTURE/answer"
exec 3< "$FIXTURE/answer"
installer_switch_variant docker > "$FIXTURE/prompt"
printf 'yes\n' > "$FIXTURE/answer"
exec 3< "$FIXTURE/answer"
installer_switch_variant native > "$FIXTURE/prompt"
[[ "$(cat "$FIXTURE/switched")" == $'to-docker\nto-native' ]]
exec 3<&-

INSTALL_INTERACTIVE=0
unset FIREWALL_UI_SWITCH_CONFIRM || true
if installer_switch_variant docker > "$FIXTURE/noninteractive" 2>&1; then
  echo 'Unconfirmed noninteractive replacement succeeded' >&2; exit 1
fi
[[ "$(cat "$FIXTURE/switched")" == $'to-docker\nto-native' ]]
FIREWALL_UI_SWITCH_CONFIRM=1 installer_switch_variant docker > /dev/null
[[ "$(tail -n 1 "$FIXTURE/switched")" == to-docker ]]

# JSON edits preserve unrelated panel settings, including traffic history pointers.
printf '{"listenHost":"0.0.0.0","listenPort":9443,"publicHost":"test.example.org","tlsCert":"/old/fullchain.pem","tlsKey":"/old/privkey.pem","statePath":"/var/lib/firewall-ui/state.json","updateChannel":"dev"}\n' > "$FIXTURE/config.json"
switch_rewrite_file "$FIXTURE/config.json" /old/ /new/
[[ "$(cat "$FIXTURE/config.json")" == *'"tlsCert":"/new/fullchain.pem"'* ]]
[[ "$(cat "$FIXTURE/config.json")" == *'"updateChannel":"dev"'* ]]
cat > "$FIXTURE/docker.env" <<'ENV'
FIREWALL_UI_DOCKER_HOST=127.0.0.1
FIREWALL_UI_DOCKER_PORT=8088
FIREWALL_UI_DOCKER_PORTS=1
FIREWALL_UI_PUBLIC_HOST=
FIREWALL_UI_TLS_CERT=
FIREWALL_UI_TLS_KEY=
FIREWALL_UI_TLS_MODE=
FIREWALL_UI_OPEN_PORTS=0
ENV
switch_docker_environment "$FIXTURE/docker.env" "$FIXTURE/config.json" existing
[[ "$(grep '^FIREWALL_UI_DOCKER_PORT=' "$FIXTURE/docker.env")" == FIREWALL_UI_DOCKER_PORT=9443 ]]
[[ "$(grep '^FIREWALL_UI_DOCKER_PORTS=' "$FIXTURE/docker.env")" == FIREWALL_UI_DOCKER_PORTS=1 ]]
[[ "$(grep '^FIREWALL_UI_PUBLIC_HOST=' "$FIXTURE/docker.env")" == FIREWALL_UI_PUBLIC_HOST=test.example.org ]]
[[ "$(grep '^FIREWALL_UI_TLS_MODE=' "$FIXTURE/docker.env")" == FIREWALL_UI_TLS_MODE=existing ]]

# Only precisely labelled Firewall-UI volumes are eligible for copy and removal.
mkdir -p "$FIXTURE/volume-config" "$FIXTURE/volume-data"
docker() {
  if [[ "$1 $2" == 'volume ls' ]]; then printf 'unrelated\nconfig\ndata\n'; return 0; fi
  if [[ "$1 $2" == 'volume inspect' ]]; then
    case "${*: -1}" in
      unrelated) echo other-project;;
      config|data)
        if [[ "$*" == *Mountpoint* ]]; then echo "$FIXTURE/volume-${*: -1}"
        elif [[ "${*: -1}" == config ]]; then echo firewall-ui-config
        else echo firewall-ui-data; fi;;
    esac
    return 0
  fi
  return 1
}
switch_docker_volumes
[[ "$SWITCH_CONFIG_VOLUME" == config && "$SWITCH_DATA_VOLUME" == data ]]
[[ "$SWITCH_CONFIG_MOUNT" == "$FIXTURE/volume-config" ]]
[[ "$SWITCH_DATA_MOUNT" == "$FIXTURE/volume-data" ]]
echo 'Variant switching confirmations, metadata and settings migration tests passed'
