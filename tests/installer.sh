#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_ROOT/install.sh"
FIXTURE="$(mktemp -d)";trap 'rm -rf "$FIXTURE"' EXIT
CONFIG_DIR="$FIXTURE/etc";STATE_DIR="$FIXTURE/state";TEMP_DIR="$FIXTURE/staging"
mkdir -p "$CONFIG_DIR" "$STATE_DIR" "$TEMP_DIR"
# Only these mocked commands can run during firewall and package-manager checks.
command() { if [[ "$1" == -v ]];then [[ ",$MOCK_COMMANDS," == *",$2,"* ]];else builtin command "$@";fi; }
ufw() { echo "Status: ${MOCK_UFW:-inactive}"; }
firewall-cmd() { echo "${MOCK_FIREWALLD:-stopped}"; }
nft() { echo "${MOCK_NFT:-}"; }
iptables() { echo "${MOCK_IPTABLES:--P INPUT ACCEPT}"; }
assert_backend() { local got;got="$(detect_firewall)";[[ "$got" == "$1" ]] || { echo "expected $1 got $got";exit 1; }; }
MOCK_COMMANDS="";assert_backend none
MOCK_COMMANDS="ufw";assert_backend ufw
MOCK_COMMANDS="ufw,firewall-cmd";MOCK_FIREWALLD=running;assert_backend firewalld
MOCK_COMMANDS="nft,iptables";MOCK_NFT='table inet filter {}';assert_backend nftables
MOCK_COMMANDS="iptables";MOCK_IPTABLES='-A INPUT -j DROP';assert_backend iptables
MOCK_COMMANDS="ufw,nft";MOCK_UFW=active;assert_backend ufw
MOCK_COMMANDS=apt-get
apt-get() { printf 'apt-get %s\n' "$*" >> "$FIXTURE/packages"; }
pkg_install ufw
[[ "$(cat "$FIXTURE/packages")" == $'apt-get update\napt-get install -y ufw' ]]
MOCK_COMMANDS=pacman
pacman() { printf 'pacman %s\n' "$*" >> "$FIXTURE/packages"; }
: > "$FIXTURE/packages";pkg_install ufw
[[ "$(cat "$FIXTURE/packages")" == 'pacman -S --needed --noconfirm ufw' ]]
# A repeat install reads saved settings and leaves both files byte-for-byte unchanged.
UPDATE_CHANNEL=stable;FIREWALL_UI_NONINTERACTIVE=1;FIREWALL_UI_PASSWORD=installer-test-password
create_settings
cp "$CONFIG_DIR/config.json" "$FIXTURE/config.before";cp "$CONFIG_DIR/environment" "$FIXTURE/environment.before"
unset PANEL_HOST PANEL_PORT
FIREWALL_UI_PORT=9090;FIREWALL_UI_LISTEN_HOST=0.0.0.0;FIREWALL_UI_PASSWORD=another-test-password
create_settings
[[ "$PANEL_HOST" == 127.0.0.1 && "$PANEL_PORT" == 8088 ]]
cmp "$FIXTURE/config.before" "$CONFIG_DIR/config.json";cmp "$FIXTURE/environment.before" "$CONFIG_DIR/environment"
# Release verification must fail closed before any installation files are replaced.
MOCK_COMMANDS=sha256sum;ARCH=amd64;UPDATE_CHANNEL=stable
curl() {
 local output="";while (($#));do if [[ "$1" == -o ]];then output="$2";shift;fi;shift;done
 if [[ "$output" == */update.json ]];then cat > "$output" <<JSON
{"assets": {
  "amd64": {
    "url": "https://github.com/SawaMEN/Firewall-UI/releases/download/v1.1.1/firewall-ui-linux-amd64",
    "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
  }
}}
JSON
 else printf 'tampered binary' > "$output";fi
}
if (download_binary);then echo 'Accepted a checksum mismatch';exit 1;fi
[[ "$REPLACED" == 0 ]]
# Failed replacements restore the old binary, manager, unit and running state.
INSTALL_DIR="$FIXTURE/install";MANAGER="$FIXTURE/manager";SERVICE_FILE="$FIXTURE/unit"
mkdir -p "$INSTALL_DIR"
printf 'old binary' > "$TEMP_DIR/previous-binary"
printf 'old manager' > "$TEMP_DIR/previous-manager"
printf 'old unit' > "$TEMP_DIR/previous-service"
printf 'old installer' > "$TEMP_DIR/previous-installer"
printf 'new installer' > "$INSTALL_DIR/install.sh"
printf 'new binary' > "$INSTALL_DIR/firewall-ui"
systemctl() { printf '%s\n' "$*" >> "$FIXTURE/systemctl"; }
REPLACED=1;HAD_BINARY=1;WAS_ACTIVE=1;WAS_ENABLED=1
cleanup
[[ "$(cat "$INSTALL_DIR/firewall-ui")" == 'old binary' ]]
[[ "$(cat "$MANAGER")" == 'old manager' && "$(cat "$SERVICE_FILE")" == 'old unit' ]]
[[ "$(cat "$INSTALL_DIR/install.sh")" == 'old installer' ]]
[[ "$(tail -n 1 "$FIXTURE/systemctl")" == 'restart firewall-ui.service' ]]
printf 'Installer firewall detection, repeat-install, checksum and rollback tests passed\n'

# Native installation must not run alongside an active Compose panel.
MOCK_COMMANDS=docker
docker() { printf '%s' "${MOCK_RUNNING_COMPOSE:-}"; }
MOCK_RUNNING_COMPOSE=firewall-ui
if installer_require_native_exclusive; then echo 'Allowed simultaneous panels'; exit 1; fi
MOCK_RUNNING_COMPOSE=''
installer_require_native_exclusive
