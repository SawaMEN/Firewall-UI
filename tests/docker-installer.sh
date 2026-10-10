#!/usr/bin/env bash
set -Eeuo pipefail
TASK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE="$(mktemp -d)"; trap 'rm -rf -- "$FIXTURE"' EXIT
source "$TASK_ROOT/deploy/firewall-ui-docker"
DOCKER_DIR="$FIXTURE/install"; DOCKER_MANAGER="$FIXTURE/manager"
DOCKER_INTERACTIVE=0
export FIREWALL_UI_USERNAME=admin FIREWALL_UI_PASSWORD='1$HOME`id`"\' FIREWALL_UI_DOCKER_HOST=127.0.0.1
export FIREWALL_UI_DOCKER_PORTS=1 FIREWALL_UI_PORT=8088
mkdir -p "$FIXTURE/volume"
# No real Docker, firewall, package or service operations are permitted here.
docker_require_engine() { :; }
systemctl() { return 1; }
sleep() { :; }
docker_download_source() {
 rm -rf "$DOCKER_DIR/source.previous"
 [[ ! -d "$DOCKER_DIR/source" ]] || mv "$DOCKER_DIR/source" "$DOCKER_DIR/source.previous"
 mkdir -p "$DOCKER_DIR/source"; touch "$DOCKER_DIR/source/compose.yaml"
}
docker() {
 printf '%s\n' "$*" >> "$FIXTURE/commands"
 if [[ "$1" == inspect && "$*" == *'.State.Running'* ]]; then echo 'true false'; return; fi
 if [[ "$1" == network && "$2" == inspect ]]; then return 1; fi
 if [[ "$1" == compose ]]; then
  case "$*" in
   *'ps -q firewall-ui') echo fixture-container;;
   *'build') return "${MOCK_BUILD_RESULT:-0}";;
   *'-cleanup-firewall') return "${MOCK_CLEANUP_RESULT:-0}";;
   *'--entrypoint sh firewall-ui -c'*)
    local -a args=("$@")
    local index
    for index in "${!args[@]}"; do
      if [[ "${args[index]}" == -c ]]; then break; fi
    done
    local script="${args[index+1]}"
    script="${script//\/etc\/firewall-ui/$FIXTURE/volume}"
    sh -c "$script" "${args[@]:index+2}";;
  esac
 fi
}

docker_install install
[[ "$(cat "$DOCKER_DIR/deployment")" == host && "$(cat "$DOCKER_DIR/password")" == "$FIREWALL_UI_PASSWORD" ]]
[[ "$(stat -c %a "$DOCKER_DIR/password")" == 600 && "$(stat -c %a "$DOCKER_DIR")" == 700 ]]
[[ "$(cat "$FIXTURE/commands")" != *'network connect'* ]]
[[ "$(cat "$FIXTURE/volume/environment")" == *'FIREWALL_UI_PASSWORD="1$HOME`id`\"\\"'* ]]
# Web changes survive an update; the installer must not rewrite credentials or settings.
printf 'FIREWALL_UI_USERNAME="web-user"\nFIREWALL_UI_PASSWORD="web-password"\n' > "$FIXTURE/volume/environment"
cp "$FIXTURE/volume/environment" "$FIXTURE/web-before"
: > "$FIXTURE/commands"
docker_install install
cmp "$FIXTURE/web-before" "$FIXTURE/volume/environment"
[[ "$(cat "$FIXTURE/commands")" != *'-save-config'* ]]
# Existing retired network deployments migrate without losing web credentials.
printf 'proxy\n' > "$DOCKER_DIR/deployment"
touch "$DOCKER_DIR/source/compose.proxy.yaml"
printf 'FIREWALL_UI_PROXY_NETWORK=retired\n' >> "$DOCKER_DIR/docker.env"
: > "$FIXTURE/commands"
docker_install install
[[ "$(cat "$DOCKER_DIR/deployment")" == host ]]
[[ "$(cat "$DOCKER_DIR/docker.env")" != *PROXY_NETWORK* ]]
[[ "$(cat "$FIXTURE/commands")" == *'source.previous/compose.proxy.yaml'* ]]
[[ ! -e "$DOCKER_DIR/source.previous" ]]
cmp "$FIXTURE/web-before" "$FIXTURE/volume/environment"
# Reset uses the current web username, not the original bootstrap username.
FIREWALL_UI_PASSWORD='new$`id`"\'
docker_reset_password
[[ "$(cat "$FIXTURE/volume/environment")" == *'FIREWALL_UI_USERNAME="web-user"'* ]]
[[ "$(cat "$FIXTURE/volume/environment")" == *'FIREWALL_UI_PASSWORD="new$`id`\"\\"'* ]]
# A build failure restores installer settings without deleting the installation.
cp "$DOCKER_DIR/docker.env" "$FIXTURE/env-before"
export MOCK_BUILD_RESULT=1 FIREWALL_UI_PORT=9090
if (docker_install configure); then echo 'Ignored failed Docker build'; exit 1; fi
cmp "$FIXTURE/env-before" "$DOCKER_DIR/docker.env"
[[ -d "$DOCKER_DIR/source" ]]
unset MOCK_BUILD_RESULT
# Never remove files/volumes after failed cleanup; remove them after success.
export MOCK_CLEANUP_RESULT=1
if docker_uninstall; then echo 'Ignored failed Docker cleanup'; exit 1; fi
[[ -f "$DOCKER_DIR/password" && -f "$DOCKER_MANAGER" ]]
export MOCK_CLEANUP_RESULT=0
docker_uninstall
[[ ! -e "$DOCKER_DIR" && ! -e "$DOCKER_MANAGER" ]]
[[ "$(cat "$FIXTURE/commands")" == *'down -v --remove-orphans'* ]]
echo 'Docker installer settings, literal passwords, update preservation, reset and purge passed'
