#!/usr/bin/env bash
set -Eeuo pipefail
TASK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE="$(mktemp -d)"; trap 'rm -rf -- "$FIXTURE"' EXIT
source "$TASK_ROOT/deploy/firewall-ui-docker"
DOCKER_DIR="$FIXTURE/install"; DOCKER_MANAGER="$FIXTURE/manager"
export FIREWALL_UI_MANAGER="$FIXTURE/fw-ui" FIREWALL_UI_LEGACY_MANAGER="$FIXTURE/legacy-native"
export FIREWALL_UI_LEGACY_DOCKER_MANAGER="$FIXTURE/legacy-docker" FIREWALL_UI_NATIVE_BINARY="$FIXTURE/native-binary"
PUBLIC_MANAGER="$FIREWALL_UI_MANAGER"; LEGACY_DOCKER_MANAGER="$FIREWALL_UI_LEGACY_DOCKER_MANAGER"
DOCKER_INTERACTIVE=0
export MOCK_RESOURCES=1
export FIREWALL_UI_USERNAME=admin FIREWALL_UI_PASSWORD='1$HOME`id`"\' FIREWALL_UI_DOCKER_HOST=127.0.0.1
export FIREWALL_UI_DOCKER_PORTS=1 FIREWALL_UI_PORT=8088
mkdir -p "$FIXTURE/volume"
# No real Docker, firewall, package or service operations are permitted here.
docker_require_engine() { :; }
docker_download_image() { printf 'download image\n' >> "$FIXTURE/commands"; return "${MOCK_IMAGE_RESULT:-0}"; }
systemctl() { return 1; }
sleep() { :; }
docker_download_source() {
 rm -rf "$DOCKER_DIR/source.previous"
 [[ ! -d "$DOCKER_DIR/source" ]] || mv "$DOCKER_DIR/source" "$DOCKER_DIR/source.previous"
 mkdir -p "$DOCKER_DIR/source"; touch "$DOCKER_DIR/source/compose.yaml"
 cp "$TASK_ROOT/install.sh" "$DOCKER_DIR/source/install.sh"
 cp "$TASK_ROOT/deploy/firewall-ui" "$DOCKER_DIR/source/firewall-manager"
}
docker() {
 printf '%s\n' "$*" >> "$FIXTURE/commands"
 if [[ "$1 ${2:-}" == 'image inspect' && "$*" == *'{{.Id}}'* ]]; then echo previous-image; return 0; fi
 if [[ "$1" == inspect && "$*" == *'.State.Running'* ]]; then echo 'true false'; return; fi
 if [[ "$1" == network && "$2" == inspect ]]; then return 1; fi
 if [[ "$1" == ps && "${MOCK_RESOURCES:-0}" == 1 && "${MOCK_CONTAINER_REMOVED:-0}" == 0 ]]; then echo fixture-container; return 0; fi
 if [[ "$1 ${2:-}" == 'volume ls' && "${MOCK_RESOURCES:-0}" == 1 ]]; then
  [[ "${MOCK_VOLUMES_REMOVED:-0}" == 1 ]] || printf 'fixture-config\nfixture-data\n'
  printf 'foreign-volume\n'; return 0
 fi
 if [[ "$1" == rm && "$*" == *fixture-container* ]]; then MOCK_CONTAINER_REMOVED=1; return 0; fi
 if [[ "$1 ${2:-}" == 'volume rm' && "$*" == *fixture-data* ]]; then MOCK_VOLUMES_REMOVED=1; return 0; fi
 if [[ "$1" == run && "$*" == *-version* ]]; then echo "${MOCK_LOCAL_VERSION:-1.2.21}"; return 0; fi
 if [[ "$1 ${2:-}" == 'volume inspect' ]]; then
  case "${@: -1}" in fixture-config) echo firewall-ui-config;; fixture-data) echo firewall-ui-data;; foreign-volume) echo other-service-data;; esac
  return 0
 fi
 if [[ "$1" == run && "$*" == *-cleanup-firewall* ]]; then return "${MOCK_CLEANUP_RESULT:-0}"; fi
 if [[ "$1" == compose ]]; then
  case "$*" in
   *'ps -q firewall-ui') echo fixture-container;;
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
# An image download failure restores installer settings without deleting the installation.
cp "$DOCKER_DIR/docker.env" "$FIXTURE/env-before"
export MOCK_IMAGE_RESULT=1 FIREWALL_UI_PORT=9090
if (docker_install configure); then echo 'Ignored failed image download'; exit 1; fi
cmp "$FIXTURE/env-before" "$DOCKER_DIR/docker.env"
[[ -d "$DOCKER_DIR/source" ]]
unset MOCK_IMAGE_RESULT
# A late command-install failure restores both existing helpers and runtime settings.
cp "$PUBLIC_MANAGER" "$FIXTURE/public-before"
cp "$DOCKER_MANAGER" "$FIXTURE/docker-before"
(
 install() {
   [[ "${*: -1}" != "$PUBLIC_MANAGER" ]] || return 1
   command install "$@"
 }
 if docker_install configure; then echo 'Ignored failed public-command replacement'; exit 1; fi
)
cmp "$PUBLIC_MANAGER" "$FIXTURE/public-before"
cmp "$DOCKER_MANAGER" "$FIXTURE/docker-before"
# Purge removes the owned old Compose helper too.
cp "$TASK_ROOT/deploy/firewall-ui-docker" "$LEGACY_DOCKER_MANAGER"
# Never remove files/volumes after failed cleanup; remove them after success.
export MOCK_CLEANUP_RESULT=1
if docker_uninstall; then echo 'Ignored failed Docker cleanup'; exit 1; fi
[[ -f "$DOCKER_DIR/password" && -f "$DOCKER_MANAGER" ]]
export MOCK_CLEANUP_RESULT=0 MOCK_IMAGE_RESULT=1
: > "$FIXTURE/commands"
docker_uninstall
[[ ! -e "$DOCKER_DIR" && ! -e "$DOCKER_MANAGER" && ! -e "$PUBLIC_MANAGER" && ! -e "$LEGACY_DOCKER_MANAGER" ]]
[[ "$(cat "$FIXTURE/commands")" == *'volume rm fixture-data'* ]]
[[ "$(cat "$FIXTURE/commands")" != *'volume rm foreign-volume'* ]]
[[ "$(cat "$FIXTURE/commands")" != *'download image'* ]]
[[ "$(cat "$FIXTURE/commands")" == *'label=com.docker.compose.service=firewall-ui'* ]]
unset MOCK_IMAGE_RESULT
# Old cleanup images must be upgraded; failed download preserves the installation.
(
 export MOCK_LOCAL_VERSION=1.2.17 MOCK_IMAGE_RESULT=1
 mkdir -p "$DOCKER_DIR"; touch "$DOCKER_DIR/.installer-managed"
 if docker_uninstall; then echo 'Removed with an outdated cleanup image'; exit 1; fi
 [[ -e "$DOCKER_DIR/.installer-managed" ]]
)
echo 'Docker installer settings, literal passwords, update preservation, reset and purge passed'

# Missing metadata and empty leftovers no longer require an installed binary.
mkdir -p "$DOCKER_DIR"; touch "$DOCKER_DIR/.installer-managed"
docker_uninstall
[[ ! -e "$DOCKER_DIR" ]]
export MOCK_RESOURCES=0
mkdir -p "$DOCKER_DIR"
: > "$FIXTURE/commands"
docker_uninstall
[[ ! -e "$DOCKER_DIR" && "$(cat "$FIXTURE/commands")" != *'download image'* ]]

# Verify checksums before loading ready images; never invoke a local build.
(
 source "$TASK_ROOT/deploy/firewall-ui-docker"
 printf 'ready-image-fixture' > "$FIXTURE/image.tar.gz"
 export FIREWALL_UI_DOCKER_IMAGE_ARCHIVE="$FIXTURE/image.tar.gz"
 export FIREWALL_UI_DOCKER_IMAGE_SHA256="$(sha256sum "$FIREWALL_UI_DOCKER_IMAGE_ARCHIVE" | awk '{print $1}')"
 : > "$FIXTURE/commands"
 docker_download_image
 [[ "$(cat "$FIXTURE/commands")" == *'load -i'* ]]
 : > "$FIXTURE/commands"
 export FIREWALL_UI_DOCKER_IMAGE_SHA256="$(printf '%064d' 0)"
 if docker_download_image; then echo 'Loaded corrupt image'; exit 1; fi
 [[ "$(cat "$FIXTURE/commands")" != *'load -i'* ]]
)
# A failed first download leaves no fake installation folder behind.
(
 DOCKER_DIR="$FIXTURE/failed-first-install"
 export MOCK_IMAGE_RESULT=1
 if docker_install install; then echo 'Ignored first image download failure'; exit 1; fi
 [[ ! -e "$DOCKER_DIR" ]]
)

# A failed first startup must stop partial containers and restore the absent
# runtime config. A retry must still perform first-install configuration.
(
 DOCKER_DIR="$FIXTURE/failed-startup"
 docker_apply_runtime_settings() { printf 'new runtime settings' > "$FIXTURE/volume/config.json"; }
 docker_wait_for_service() { return "${MOCK_START_RESULT:-0}"; }
 rm -f "$FIXTURE/volume/config.json"
 : > "$FIXTURE/commands"
 export MOCK_START_RESULT=1
 if docker_install install; then echo 'Ignored failed first startup'; exit 1; fi
 [[ ! -e "$DOCKER_DIR/deployment" && ! -e "$FIXTURE/volume/config.json" ]]
 [[ "$(cat "$FIXTURE/commands")" == *' stop'* ]]
 export MOCK_START_RESULT=0
 docker_install install
 [[ -e "$DOCKER_DIR/deployment" && -s "$FIXTURE/volume/config.json" ]]
 # Configuration failure must restore the runtime file, metadata and image.
 cp "$DOCKER_DIR/docker.env" "$FIXTURE/start-env-before"
 printf 'previous runtime settings' > "$FIXTURE/volume/config.json"
 export MOCK_START_RESULT=1 FIREWALL_UI_PORT=10090
 : > "$FIXTURE/commands"
 if docker_install configure; then echo 'Ignored failed reconfiguration'; exit 1; fi
 cmp "$FIXTURE/start-env-before" "$DOCKER_DIR/docker.env"
 [[ "$(cat "$FIXTURE/volume/config.json")" == 'previous runtime settings' ]]
 [[ "$(cat "$FIXTURE/commands")" == *'tag previous-image firewall-ui:stable'* ]]
 [[ "$(cat "$FIXTURE/commands")" == *' up -d --no-build'* ]]
)
echo 'Failed Docker startup and runtime rollback/retry passed'

# Username changes use the same literal, atomic volume format as password reset.
(
 DOCKER_DIR="$FIXTURE/failed-startup"
 FIREWALL_UI_USERNAME='console-user'; FIREWALL_UI_PASSWORD='console$pass'
 docker_change_credentials
 [[ "$(cat "$DOCKER_DIR/username")" == console-user ]]
 [[ "$(cat "$FIXTURE/volume/environment")" == *'FIREWALL_UI_USERNAME="console-user"'* ]]
 [[ "$(cat "$FIXTURE/volume/environment")" == *'FIREWALL_UI_PASSWORD="console$pass"'* ]]
)

# Native and Compose share domain/IP certificate choices and HTTPS runtime flags.
(
 DOCKER_DIR="$FIXTURE/tls-wizard"
 mkdir -p "$DOCKER_DIR/source"
 cp "$TASK_ROOT/install.sh" "$DOCKER_DIR/source/install.sh"
 cp "$TASK_ROOT/deploy/firewall-ui" "$DOCKER_DIR/source/firewall-manager"
 cp "$TASK_ROOT/deploy/docker/compose.tls.yaml" "$DOCKER_DIR/source/compose.tls.yaml"
 printf admin > "$DOCKER_DIR/username"; printf 1 > "$DOCKER_DIR/password"
 unset FIREWALL_UI_DOCKER_HOST FIREWALL_UI_PORT
 DOCKER_INTERACTIVE=1
 printf '2\npanel.example.com\n3\n9443\nn\nn\n' > "$FIXTURE/tls-answers"; exec 3<>"$FIXTURE/tls-answers"
 docker_select_settings
 cert="$(docker_read_setting FIREWALL_UI_TLS_CERT '')"
 openssl x509 -in "$cert" -noout -checkhost panel.example.com
 [[ "$(docker_read_setting FIREWALL_UI_PUBLIC_HOST '')" == panel.example.com ]]
 [[ "$(docker_show_access)" == *https://panel.example.com:9443/* ]]
 : > "$FIXTURE/commands"
 docker_apply_runtime_settings
 [[ "$(cat "$FIXTURE/commands")" == *compose.tls.yaml* && "$(cat "$FIXTURE/commands")" == *'-secure-cookies=true'* ]]
 [[ "$(cat "$FIXTURE/commands")" == *'-public-host panel.example.com'* ]]
 # Switching back to local access explicitly clears all TLS/public-address fields.
 printf '1\n8088\nn\n' > "$FIXTURE/tls-answers"; exec 3<>"$FIXTURE/tls-answers"
 docker_select_settings
 [[ -z "$(docker_read_setting FIREWALL_UI_TLS_CERT '')" && -z "$(docker_read_setting FIREWALL_UI_PUBLIC_HOST '')" ]]
)
echo 'Shared Compose HTTPS wizard, certificate mount and local-mode reset passed'

# The real source downloader maps repository paths to stable installed filenames.
(
 DOCKER_DIR="$FIXTURE/layout-download"; mkdir -p "$DOCKER_DIR"
 export FIREWALL_UI_DOCKER_SOURCE="$TASK_ROOT"
 # Re-source to exercise the production function instead of the earlier mock.
 source "$TASK_ROOT/deploy/firewall-ui-docker"
 DOCKER_DIR="$FIXTURE/layout-download"
 docker_download_source
 for file in compose.yaml compose.docker-ports.yaml compose.tls.yaml install.sh firewall-manager; do
   [[ -s "$DOCKER_DIR/source/$file" ]]
 done
 [[ ! -d "$DOCKER_DIR/source/deploy" ]]
)
echo 'Organized Docker source paths and saved installer filenames passed'
