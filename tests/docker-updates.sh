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
# Empty Docker passwords must be generated just like native passwords.
DOCKER_INTERACTIVE=0
FIREWALL_UI_PASSWORD='' docker_password > "$FIXTURE/password-output"
[[ "$DOCKER_PASSWORD" =~ ^[0-9a-f]{40}$ ]]
grep -q "Сгенерированный пароль Firewall-UI: $DOCKER_PASSWORD" "$FIXTURE/password-output"
export FIREWALL_UI_DOCKER_AUTO_UPDATE=1
systemctl() { printf '%s\n' "$*" >> "$FIXTURE/systemctl"; }
docker_choose_auto_update
docker_setup_updates
grep -q 'auto-update stable' "$SYSTEMD_DIR/firewall-ui-docker-update.service"
grep -q 'OnCalendar=hourly' "$SYSTEMD_DIR/firewall-ui-docker-update.timer"
grep -q 'enable --now firewall-ui-docker-update.timer' "$FIXTURE/systemctl"
grep -q 'auto-update dev' "$SYSTEMD_DIR/firewall-ui-docker-dev-update.service"
grep -q 'OnCalendar=\*-\*-\* \*:00/30:00' "$SYSTEMD_DIR/firewall-ui-docker-dev-update.timer"
grep -q 'enable --now firewall-ui-docker-dev-update.timer' "$FIXTURE/systemctl"
export FIREWALL_UI_DOCKER_AUTO_UPDATE=0
docker_choose_auto_update
docker_setup_updates
grep -qx 0 "$DOCKER_DIR/auto-update"
grep -q 'disable --now firewall-ui-docker-update.timer' "$FIXTURE/systemctl"
test -e "$SYSTEMD_DIR/firewall-ui-docker-dev-update.timer"
docker_remove_updates
for unit in firewall-ui-docker-update firewall-ui-docker-dev-update; do
  test ! -e "$SYSTEMD_DIR/$unit.service"
  test ! -e "$SYSTEMD_DIR/$unit.timer"
done

docker_update_safe() { return "${MOCK_UPDATE_BLOCKED:-0}"; }
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
  cp "$FIREWALL_UI_DOCKER_MANIFEST_FILE" "$FIXTURE/last-installed-manifest"
  printf 'install called\n' >> "$FIXTURE/install"
  return "${MOCK_UPDATE_FAILURE:-0}"
}
MANAGER
  fi
}
printf '%s\n' "$SHA" > "$DOCKER_DIR/image.sha256"
MOCK_UPDATE_BLOCKED=1
docker_auto_update
grep -q '"phase":"deferred"' "$DOCKER_DIR/update-status.json"
test ! -e "$FIXTURE/curl"
unset MOCK_UPDATE_BLOCKED
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
# A dev panel follows the dev manifest and pinned commit without confirmation.
printf '{"updateChannel":"dev"}\n' > "$DOCKER_CONFIG_DIR/config.json"
# A dev installation does not ask and updates even with stable opted out.
docker_ask() { echo 'Unexpected Docker dev confirmation' >&2; return 19; }
docker_choose_auto_update
unset -f docker_ask
grep -qx 0 "$DOCKER_DIR/auto-update"
COUNT="$(wc -l < "$FIXTURE/curl")"
docker_auto_update stable
test "$(wc -l < "$FIXTURE/curl")" == "$COUNT"
sed -i -e 's/"version": "1.3.99"/"version": "dev-bbbbbbb"/' \
  -e 's/"channel": "stable"/"channel": "dev"/' \
  -e 's|/releases/download/v1.3.99/|/releases/download/dev/|g' "$FIXTURE/manifest"
unset MOCK_UPDATE_FAILURE
docker_auto_update dev
grep -q '/releases/download/dev/update.json' "$FIXTURE/curl"
grep -q '"version": "dev-bbbbbbb"' "$FIXTURE/last-installed-manifest"
grep -q 'install called' "$FIXTURE/install"

docker_compose() { return 0; }
COUNT="$(wc -l < "$FIXTURE/curl")"
docker_auto_update
test "$(wc -l < "$FIXTURE/curl")" == "$COUNT"
printf 'Docker password generation, stable hourly opt-in, automatic dev half-hour checks, channel isolation, removal and update safety passed\n'
