#!/usr/bin/env bash
set -Eeuo pipefail
TASK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE="$(mktemp -d)"
trap 'rm -rf -- "$FIXTURE"' EXIT
export TASK_ROOT FIXTURE
cat > "$FIXTURE/runner" <<'SCRIPT'
#!/usr/bin/env bash
set -Eeuo pipefail
source "$TASK_ROOT/deploy/firewall-ui"
require_root() { :; } # All paths and service commands below are isolated mocks.
INSTALL_DIR="$FIXTURE/install"; BIN="$INSTALL_DIR/firewall-ui"; CONFIG="$FIXTURE/config"
export TMPDIR="$FIXTURE/downloads"
curl() {
  local destination=''
  while (($#)); do
    if [[ "$1" == -o ]]; then destination="$2"; shift; fi
    shift
  done
  if [[ "$destination" == */update.json ]]; then cp "$FIXTURE/manifest" "$destination";
  else cp "$FIXTURE/candidate" "$destination"; fi
}
sleep() { :; }
systemctl() {
  printf '%s\n' "$*" >> "$FIXTURE/systemctl"
  case "$1" in
    is-active)
      [[ "${SCENARIO:-}" != inactive && ( "${SCENARIO:-}" != unhealthy || "$(cat "$BIN")" == *'# old'* ) ]];;
    restart)
      [[ "${SCENARIO:-}" != restart-failure || "$(cat "$BIN")" == *'# old'* ]];;
  esac
}
case "$ACTION" in
  rollback) rollback_binary;;
  download) FIREWALL_UI_NONINTERACTIVE=1 update_binary;;
  *) replace_binary "$FIXTURE/candidate";;
esac
SCRIPT
prepare() {
  mkdir -p "$FIXTURE/install" "$FIXTURE/downloads"
  printf '#!/usr/bin/env bash\n# old\nexit 0\n' > "$FIXTURE/install/firewall-ui"
  printf '#!/usr/bin/env bash\n# previous\nexit 0\n' > "$FIXTURE/install/firewall-ui.previous"
  printf '#!/usr/bin/env bash\n# new\nexit 0\n' > "$FIXTURE/candidate"
  chmod +x "$FIXTURE/install/"* "$FIXTURE/candidate"
  : > "$FIXTURE/systemctl"
}
prepare
ACTION=update bash "$FIXTURE/runner"
[[ "$(cat "$FIXTURE/install/firewall-ui")" == *'# new'* ]]
[[ "$(cat "$FIXTURE/install/firewall-ui.previous")" == *'# old'* ]]
ACTION=rollback bash "$FIXTURE/runner"
[[ "$(cat "$FIXTURE/install/firewall-ui")" == *'# old'* ]]
[[ "$(cat "$FIXTURE/install/firewall-ui.previous")" == *'# new'* ]]
for scenario in unhealthy restart-failure; do
  prepare
  if SCENARIO="$scenario" ACTION=update bash "$FIXTURE/runner"; then echo 'Accepted a broken service' >&2; exit 1; fi
  [[ "$(cat "$FIXTURE/install/firewall-ui")" == *'# old'* ]]
  [[ "$(cat "$FIXTURE/install/firewall-ui.previous")" == *'# previous'* ]]
  [[ "$(tail -n 1 "$FIXTURE/systemctl")" == 'restart firewall-ui.service' ]]
done
prepare
printf '#!/usr/bin/env bash\nexit 1\n' > "$FIXTURE/candidate"
if ACTION=update bash "$FIXTURE/runner"; then echo 'Accepted invalid configuration' >&2; exit 1; fi
[[ ! -s "$FIXTURE/systemctl" ]]
[[ "$(cat "$FIXTURE/install/firewall-ui")" == *'# old'* ]]
[[ -z "$(find "$FIXTURE/install" -maxdepth 1 -name '.replace-*' -print)" ]]
prepare
case "$(uname -m)" in x86_64|amd64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; esac
SHA="$(sha256sum "$FIXTURE/candidate" | cut -d ' ' -f 1)"
cat > "$FIXTURE/manifest" <<JSON
{"assets": {
  "$ARCH": {
    "url": "https://github.com/SawaMEN/Firewall-UI/releases/download/dev/firewall-ui-linux-$ARCH",
    "sha256": "$SHA"
  }
}}
JSON
ACTION=download bash "$FIXTURE/runner"
[[ "$(cat "$FIXTURE/install/firewall-ui")" == *'# new'* ]]
prepare
sed -i 's@releases/download/dev@blob/main@' "$FIXTURE/manifest"
if ACTION=download bash "$FIXTURE/runner"; then echo 'Accepted invalid release URL'; exit 1; fi
[[ ! -s "$FIXTURE/systemctl" && "$(cat "$FIXTURE/install/firewall-ui")" == *'# old'* ]]
sed -i 's@blob/main@releases/download/dev@' "$FIXTURE/manifest"
printf 'tampered' >> "$FIXTURE/candidate"
if ACTION=download bash "$FIXTURE/runner"; then echo 'Accepted tampered binary'; exit 1; fi
[[ ! -s "$FIXTURE/systemctl" && "$(cat "$FIXTURE/install/firewall-ui")" == *'# old'* ]]
[[ -z "$(find "$FIXTURE/downloads" -mindepth 1 -print)" ]]
printf 'Manager replacement, configuration checks, health rollback and version swap tests passed\n'

# fw-ui uses the saved Compose menu and delegates commands without network access.
(
 source "$TASK_ROOT/deploy/firewall-ui"
 require_root() { :; }
 INSTALL_DIR="$FIXTURE/absent-native"; BIN="$INSTALL_DIR/firewall-ui"
 DOCKER_INSTALL_DIR="$FIXTURE/compose"; DOCKER_MANAGER_PATH="$FIXTURE/fw-ui-docker"
 mkdir -p "$DOCKER_INSTALL_DIR"; touch "$DOCKER_INSTALL_DIR/deployment"
 printf '#!/bin/bash\nprintf "compose %%s\n" "$*"\n' > "$DOCKER_MANAGER_PATH"; chmod +x "$DOCKER_MANAGER_PATH"
 printf '#!/bin/bash\nprintf "saved menu %%s\n" "$*"\n' > "$DOCKER_INSTALL_DIR/install.sh"
 [[ "$(main restart)" == 'compose restart' ]]
 mkdir -p "$INSTALL_DIR"; touch "$BIN"; chmod +x "$BIN"
 systemctl() { return 1; }
 [[ "$(main restart)" == 'compose restart' ]]
 [[ "$(main uninstall --purge)" == 'saved menu --uninstall' ]]
 [[ "$(main)" == 'saved menu --menu' ]]
 systemctl() { printf 'native %s\n' "$*"; }
 [[ "$(FIREWALL_UI_MANAGER_VARIANT=native main restart)" == 'native restart firewall-ui.service' ]]
 MANAGER_PATH="$FIXTURE/fw-ui"; LEGACY_MANAGER_PATH="$FIXTURE/firewall-ui"
 cp "$TASK_ROOT/deploy/firewall-ui" "$LEGACY_MANAGER_PATH"
 remove_legacy_manager
 [[ ! -e "$LEGACY_MANAGER_PATH" ]]
 printf 'foreign executable\n' > "$LEGACY_MANAGER_PATH"
 remove_legacy_manager
 [[ -f "$LEGACY_MANAGER_PATH" ]]
)
echo 'fw-ui Compose dispatch, offline menu and owned legacy command migration passed'
