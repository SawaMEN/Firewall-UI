#!/usr/bin/env bash
set -Eeuo pipefail
TASK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$TASK_ROOT/deploy/firewall-ui"
FIXTURE="$(mktemp -d)"
trap 'rm -rf -- "$FIXTURE"' EXIT
INSTALL_DIR="$FIXTURE/install"; BIN="$INSTALL_DIR/firewall-ui"
CONFIG_DIR="$FIXTURE/config"; CONFIG="$CONFIG_DIR/config.json"
STATE_DIR="$FIXTURE/state"; UNIT_DIR="$FIXTURE/units"; MANAGER_PATH="$FIXTURE/manager"
require_root() { :; }
systemctl() { printf '%s\n' "$*" >> "$FIXTURE/systemctl"; [[ "$1" != is-active ]]; }
prepare() {
 mkdir -p "$INSTALL_DIR" "$CONFIG_DIR/tls" "$STATE_DIR" "$UNIT_DIR"
 printf 'credential' > "$CONFIG_DIR/environment"
 printf 'certificate' > "$CONFIG_DIR/tls/cert.pem"
 printf 'state' > "$STATE_DIR/state.json"
 touch "$UNIT_DIR/firewall-ui.service" "$UNIT_DIR/firewall-ui-cert-renew.service" "$UNIT_DIR/firewall-ui-cert-renew.timer" "$MANAGER_PATH"
 cat > "$BIN" <<'BIN'
#!/usr/bin/env bash
[[ "$*" == *'-cleanup-firewall'* ]] || exit 3
exit "${CLEANUP_RESULT:-0}"
BIN
 chmod +x "$BIN"
}
prepare
export CLEANUP_RESULT=1
if uninstall_service --purge; then echo 'Ignored failed rule cleanup'; exit 1; fi
[[ -f "$CONFIG_DIR/environment" && -x "$BIN" && -f "$STATE_DIR/state.json" && -f "$MANAGER_PATH" ]]
export CLEANUP_RESULT=0
FIREWALL_UI_NONINTERACTIVE=0
uninstall_service <<< 'n'
[[ ! -d "$INSTALL_DIR" && -f "$CONFIG_DIR/environment" && -f "$STATE_DIR/state.json" ]]
prepare
printf 'foreign firewall configuration' > "$FIXTURE/foreign-firewall"
uninstall_service <<< 'y'
[[ ! -d "$INSTALL_DIR" && ! -d "$CONFIG_DIR" && ! -d "$STATE_DIR" && ! -f "$MANAGER_PATH" ]]
[[ -f "$FIXTURE/foreign-firewall" && ! -f "$UNIT_DIR/firewall-ui-cert-renew.timer" ]]
[[ "$(cat "$FIXTURE/systemctl")" == *'stop firewall-ui.service firewall-ui-cert-renew.timer firewall-ui-cert-renew.service'* ]]
# Installer records only a newly added firewalld layer; existing runtime ports
# belong to the administrator and must survive removal.
source "$TASK_ROOT/install.sh"
STATE_DIR="$FIXTURE/access-state"; OPEN_PORTS=1
detect_firewall() { echo firewalld; }
firewall-cmd() {
 printf '%s\n' "$*" >> "$FIXTURE/firewalld"
 case "$*" in
  --get-default-zone) echo public;;
  *--query-port=*) [[ "$*" != *--permanent* ]];;
 esac
}
allow_access_port 8443
[[ "$(cat "$STATE_DIR/access-rules")" == 'permanent public 8443/tcp' ]]
firewall-cmd() {
 printf '%s\n' "$*" >> "$FIXTURE/removals"
 return 0
}
cleanup_access_rules
[[ "$(cat "$FIXTURE/removals")" == *'--permanent --zone=public --remove-port=8443/tcp'* ]]
[[ "$(cat "$FIXTURE/removals")" != *$'\n--zone=public --remove-port'* ]]
echo 'Uninstall preservation, purge, failure recovery and firewall ownership passed'
# A failed purge must not close the terminal/menu or pretend it succeeded.
(
 uninstall_service() { echo 'Fixture cleanup failure' >&2; return 1; }
 menu <<< $'10\n0'
) > "$FIXTURE/menu-output" 2>&1
[[ "$(cat "$FIXTURE/menu-output")" == *'Полное удаление не завершено.'* ]]
[[ "$(awk '/^Firewall-UI$/ {count++} END {print count}' "$FIXTURE/menu-output")" == 2 ]]
