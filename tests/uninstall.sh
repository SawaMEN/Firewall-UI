#!/usr/bin/env bash
set -Eeuo pipefail
TASK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$TASK_ROOT/deploy/firewall-ui"
FIXTURE="$(mktemp -d)"
trap 'rm -rf -- "$FIXTURE"' EXIT
INSTALL_DIR="$FIXTURE/install"; BIN="$INSTALL_DIR/firewall-ui"
CONFIG_DIR="$FIXTURE/config"; CONFIG="$CONFIG_DIR/config.json"
STATE_DIR="$FIXTURE/state"; UNIT_DIR="$FIXTURE/units"; MANAGER_PATH="$FIXTURE/manager"; LEGACY_MANAGER_PATH="$FIXTURE/legacy-manager"
DOCKER_INSTALL_DIR="$FIXTURE/compose"; DOCKER_MANAGER_PATH="$FIXTURE/compose-manager"
require_root() { :; }
sleep() { :; }
systemctl() {
 printf '%s\n' "$*" >> "$FIXTURE/systemctl"
 case "$1" in
  show)
   if [[ "$2" != firewall-ui.service ]]; then echo inactive
   elif [[ "${STOP_CASE:-normal}" == stuck ]]; then echo deactivating
   elif [[ "${STOP_CASE:-normal}" == delayed && ! -f "$FIXTURE/polled" ]]; then touch "$FIXTURE/polled"; echo deactivating
   elif [[ "${STOP_CASE:-normal}" == kill && ! -f "$FIXTURE/killed" ]]; then echo deactivating
   else echo inactive; fi;;
  stop) [[ "$*" != *cert-renew* ]];;
  kill) [[ "$*" != *SIGKILL* ]] || touch "$FIXTURE/killed";;
  is-active) return 1;;
 esac
}
prepare() {
 mkdir -p "$INSTALL_DIR" "$CONFIG_DIR/tls" "$STATE_DIR" "$UNIT_DIR"
 printf 'credential' > "$CONFIG_DIR/environment"
 printf 'certificate' > "$CONFIG_DIR/tls/cert.pem"
 printf 'state' > "$STATE_DIR/state.json"
 cp "$TASK_ROOT/deploy/firewall-ui" "$LEGACY_MANAGER_PATH"
 touch "$UNIT_DIR/firewall-ui.service" "$UNIT_DIR/firewall-ui-cert-renew.service" "$UNIT_DIR/firewall-ui-cert-renew.timer" "$MANAGER_PATH"
 cat > "$BIN" <<'BIN'
#!/usr/bin/env bash
[[ "$*" == *'-cleanup-firewall'* ]] || exit 3
exit "${CLEANUP_RESULT:-0}"
BIN
 chmod +x "$BIN"
}
prepare
STOP_CASE=stuck
if uninstall_service --purge; then echo 'Deleted a running service'; exit 1; fi
[[ -x "$BIN" && -f "$MANAGER_PATH" && -f "$CONFIG_DIR/environment" ]]
STOP_CASE=kill
uninstall_service --purge
[[ -f "$FIXTURE/killed" && ! -d "$INSTALL_DIR" ]]
prepare
STOP_CASE=delayed
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
[[ ! -d "$INSTALL_DIR" && ! -d "$CONFIG_DIR" && ! -d "$STATE_DIR" && ! -f "$MANAGER_PATH" && ! -f "$LEGACY_MANAGER_PATH" ]]
[[ -f "$FIXTURE/foreign-firewall" && ! -f "$UNIT_DIR/firewall-ui-cert-renew.timer" ]]
[[ "$(cat "$FIXTURE/systemctl")" == *'stop --no-block firewall-ui.service'* ]]
[[ "$(cat "$FIXTURE/systemctl")" == *'stop --no-block firewall-ui-cert-renew.timer'* ]]
[[ "$(cat "$FIXTURE/systemctl")" == *'kill --kill-whom=all --signal=SIGKILL firewall-ui.service'* ]]
# Old binary cleanup also restores owned IPv4/IPv6 ping restrictions.
prepare
export FIREWALL_UI_SYSCTL_DIR="$FIXTURE/sysctl"
mkdir -p "$FIREWALL_UI_SYSCTL_DIR/net/ipv4" "$FIREWALL_UI_SYSCTL_DIR/net/ipv6/icmp"
printf '1\n' > "$FIREWALL_UI_SYSCTL_DIR/net/ipv4/icmp_echo_ignore_all"
printf '1\n' > "$FIREWALL_UI_SYSCTL_DIR/net/ipv6/icmp/echo_ignore_all"
printf '{"firewallPingEnabled":"false"}' > "$STATE_DIR/state.json"
uninstall_service --purge
[[ "$(cat "$FIREWALL_UI_SYSCTL_DIR/net/ipv4/icmp_echo_ignore_all")" == 0 ]]
[[ "$(cat "$FIREWALL_UI_SYSCTL_DIR/net/ipv6/icmp/echo_ignore_all")" == 0 ]]
prepare
rm -f "$BIN"
cleanup_missing_binary() { printf 'recovered\n' > "$FIXTURE/recovery"; }
uninstall_service --purge
[[ -f "$FIXTURE/recovery" && ! -d "$INSTALL_DIR" ]]
# systemd can return an error for units that were never installed.
(
 systemctl() {
   if [[ "$*" == *LoadState* ]]; then echo not-found; return 1; fi
   return 1
 }
 stop_uninstall_unit firewall-ui-cert-renew.timer
)
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

# Host allowances created by the shared Docker wizard are removed only while owned.
(
 mkdir -p "$STATE_DIR"
 printf '8443\n9443\n' > "$STATE_DIR/access-ufw"
 ufw() {
   printf '%s\n' "$*" >> "$FIXTURE/ufw-owned-commands"
   if [[ "$*" == 'show added' ]]; then
     printf "ufw allow 8443/tcp comment 'Firewall-UI access'\nufw allow 9443/tcp comment 'administrator'\n"
   fi
 }
 cleanup_access_rules
 [[ ! -f "$STATE_DIR/access-ufw" ]]
 [[ "$(cat "$FIXTURE/ufw-owned-commands")" == *'--force delete allow 8443/tcp'* ]]
 [[ "$(cat "$FIXTURE/ufw-owned-commands")" != *'delete allow 9443/tcp'* ]]
)
echo 'Owned host UFW access cleanup and administrator-rule preservation passed'
