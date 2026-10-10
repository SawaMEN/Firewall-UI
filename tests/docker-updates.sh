#!/usr/bin/env bash
set -Eeuo pipefail
TASK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE="$(mktemp -d)"; trap 'rm -rf -- "$FIXTURE"' EXIT
source "$TASK_ROOT/deploy/firewall-ui-docker"
DOCKER_DIR="$FIXTURE/panel"; DOCKER_MANAGER="$FIXTURE/manager"
SYSTEMD_DIR="$FIXTURE/systemd"
mkdir -p "$DOCKER_DIR/source" "$SYSTEMD_DIR"
printf 'managed\n' > "$DOCKER_DIR/.installer-managed"
printf 'host\n' > "$DOCKER_DIR/deployment"
for file in docker.env username password; do printf 'fixture\n' > "$DOCKER_DIR/$file"; done
printf 'fixture\n' > "$DOCKER_DIR/source/compose.yaml"
export FIREWALL_UI_DOCKER_DIR="$DOCKER_DIR"
DOCKER_CONFIG_DIR="$FIXTURE/etc/firewall-ui"; DOCKER_STATE_DIR="$FIXTURE/var/lib/firewall-ui"
mkdir -p "$DOCKER_CONFIG_DIR" "$DOCKER_STATE_DIR"
printf '{"updateChannel":"stable"}\n' > "$DOCKER_CONFIG_DIR/config.json"
export FIREWALL_UI_DOCKER_AUTO_UPDATE=1
systemctl() { printf '%s\n' "$*" >> "$FIXTURE/systemctl"; }
docker_choose_auto_update
docker_setup_updates
grep -q 'auto-update' "$SYSTEMD_DIR/firewall-ui-docker-update.service"
grep -q 'OnCalendar=hourly' "$SYSTEMD_DIR/firewall-ui-docker-update.timer"
grep -q 'enable --now firewall-ui-docker-update.timer' "$FIXTURE/systemctl"
export FIREWALL_UI_DOCKER_AUTO_UPDATE=0
docker_choose_auto_update
docker_setup_updates
grep -qx 0 "$DOCKER_DIR/auto-update"
grep -q 'disable --now firewall-ui-docker-update.timer' "$FIXTURE/systemctl"
docker_remove_updates
test ! -e "$SYSTEMD_DIR/firewall-ui-docker-update.service"
test ! -e "$SYSTEMD_DIR/firewall-ui-docker-update.timer"

docker_compose() { [[ "$*" == 'ps -q firewall-ui' ]] && echo running-container; }
SHA="$(printf 'a%.0s' {1..64})"; COMMIT="$(printf 'b%.0s' {1..40})"
cat > "$FIXTURE/manifest" <<JSON
{
  "version": "1.3.99",
  "commit": "$COMMIT",
  "channel": "stable",
  "assets": {
    "docker-amd64": {
      "url": "https://github.com/SawaMEN/Firewall-UI/releases/download/v1.3.99/firewall-ui-docker-linux-amd64.tar.gz",
      "sha256": "$SHA"
    },
    "docker-arm64": {
      "url": "https://github.com/SawaMEN/Firewall-UI/releases/download/v1.3.99/firewall-ui-docker-linux-arm64.tar.gz",
      "sha256": "$SHA"
    }
  }
}
JSON
curl() {
  local -a args=("$@")
  local target="${args[${#args[@]}-1]}" url="${args[${#args[@]}-3]}"
  printf '%s\n' "$url" >> "$FIXTURE/curl"
  if [[ "$url" == *update.json ]]; then cp "$FIXTURE/manifest" "$target"
  else
    [[ "$url" == "https://raw.githubusercontent.com/SawaMEN/Firewall-UI/$COMMIT/deploy/firewall-ui-docker" ]] || return 1
    cat > "$target" <<'MANAGER'
docker_install() {
  [[ "$FIREWALL_UI_DOCKER_SOURCE_REF" == "$COMMIT" ]]
  [[ -f "$FIREWALL_UI_DOCKER_MANIFEST_FILE" ]]
  [[ -z "${FIREWALL_UI_DOCKER_IMAGE_ARCHIVE:-}" ]]
  printf 'install called\n' >> "$FIXTURE/install"
  return "${MOCK_UPDATE_FAILURE:-0}"
}
MANAGER
  fi
}
printf '%s\n' "$SHA" > "$DOCKER_DIR/image.sha256"
docker_auto_update
test ! -e "$FIXTURE/install"
grep -q '"phase":"success"' "$DOCKER_DIR/update-status.json"
printf 'old\n' > "$DOCKER_DIR/image.sha256"
export FIREWALL_UI_DOCKER_IMAGE_ARCHIVE=obsolete-archive
docker_auto_update
grep -q 'install called' "$FIXTURE/install"
export MOCK_UPDATE_FAILURE=7
if docker_auto_update; then echo 'Failed update reported success' >&2; exit 1; fi
grep -q '"phase":"failed"' "$DOCKER_DIR/update-status.json"
grep -qx old "$DOCKER_DIR/image.sha256"
docker_compose() { return 0; }
COUNT="$(wc -l < "$FIXTURE/curl")"
docker_auto_update
test "$(wc -l < "$FIXTURE/curl")" == "$COUNT"
printf 'Docker hourly schedule, disabling/removal, current-image skip, pinned release, failures and stopped-panel preservation passed\n'
