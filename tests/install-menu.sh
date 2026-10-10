#!/usr/bin/env bash
set -Eeuo pipefail
TASK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE="$(mktemp -d)"
trap 'rm -rf -- "$FIXTURE"' EXIT
source "$TASK_ROOT/install.sh"
INSTALL_DIR="$FIXTURE/native"; CONFIG_DIR="$FIXTURE/config"; STATE_DIR="$FIXTURE/state"
SERVICE_FILE="$FIXTURE/service"; MANAGER="$FIXTURE/native-manager"
export FIREWALL_UI_DOCKER_DIR="$FIXTURE/compose" FIREWALL_UI_DOCKER_MANAGER="$FIXTURE/compose-manager"
systemctl() { return 1; }
docker() { return 0; }
mkdir -p "$INSTALL_DIR"; printf '#!/bin/sh\nexit 0\n' > "$INSTALL_DIR/firewall-ui"; chmod +x "$INSTALL_DIR/firewall-ui"
INSTALL_INTERACTIVE=1
for selection in '1 install' '2 configure' '3 reset-password' '4 uninstall' '6 logs' '0 exit'; do
  read -r answer expected <<< "$selection"
  if [[ "$answer" == 2 ]]; then printf '2\n1\n' > "$FIXTURE/answer"
  else printf '%s\n1\n' "$answer" > "$FIXTURE/answer"; fi
  exec 3<>"$FIXTURE/answer"
  select_installer_action
  [[ "$INSTALL_ACTION" == "$expected" ]]
  exec 3>&-
done
printf '1\n2\n' > "$FIXTURE/answer"; exec 3<>"$FIXTURE/answer"
select_installer_action
[[ "$INSTALL_ACTION" == docker-install ]]
# Back returns to the main menu; invalid choices stay in the variant menu.
printf '1\n9\n0\n4\n' > "$FIXTURE/answer"; exec 3<>"$FIXTURE/answer"
select_installer_action
[[ "$INSTALL_ACTION" == uninstall ]]
printf '1\n0\n1\n2\n' > "$FIXTURE/answer"; exec 3<>"$FIXTURE/answer"
select_installer_action
[[ "$INSTALL_ACTION" == docker-install ]]
printf '5\n\n0\n'  > "$FIXTURE/answer"; exec 3<>"$FIXTURE/answer"
select_installer_action > "$FIXTURE/status"
[[ "$(cat "$FIXTURE/status")" == *'Обычная установка: установлена, остановлена'* ]]
[[ "$(cat "$FIXTURE/status")" == *'Docker Compose: не установлен'* ]]
exec 3>&-
# Reset and purge dispatch before package installation, UFW detection or updates.
FIREWALL_UI_NONINTERACTIVE=1
require_installer_root() { :; } # All service/file operations below use isolated mocks.
check_system() { echo 'Unexpected system preflight'; return 1; }
fetch_repo_file() {
  cat > "$2" <<'SCRIPT'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$TASK_MENU_LOG"
SCRIPT
}
export TASK_MENU_LOG="$FIXTURE/actions"
main --reset-password
main --uninstall
run_installer_docker_action() { printf 'docker %s\n' "$1" >> "$TASK_MENU_LOG"; }
main --docker
main --docker-configure
main --docker-reset-password
main --docker-uninstall
[[ "$(cat "$FIXTURE/actions")" == $'reset-password\nuninstall --purge\ndocker install\ndocker configure\ndocker reset-password\ndocker uninstall' ]]
for action in --compose --compose-configure --compose-reset-password --compose-uninstall; do main "$action"; done
[[ "$(tail -n 4 "$FIXTURE/actions")" == $'docker install\ndocker configure\ndocker reset-password\ndocker uninstall' ]]
# A single purge removes both variants, even if the first reports failure.
mkdir -p "$FIREWALL_UI_DOCKER_DIR"; touch "$FIREWALL_UI_DOCKER_DIR/.installer-managed"
: > "$FIXTURE/actions"
main --uninstall
[[ "$(cat "$FIXTURE/actions")" == $'docker uninstall\nuninstall --purge' ]]
run_installer_docker_action() { printf 'docker %s\n' "$1" >> "$TASK_MENU_LOG"; return 1; }
: > "$FIXTURE/actions"
if main --uninstall; then echo 'Ignored partial removal'; exit 1; fi
[[ "$(cat "$FIXTURE/actions")" == $'docker uninstall\nuninstall --purge' ]]
# Settings/reset automatically select Compose when it is the only installation.
rm -rf "$INSTALL_DIR"
run_installer_docker_action() { printf 'docker %s\n' "$1" >> "$TASK_MENU_LOG"; }
: > "$FIXTURE/actions"
main --reset-password
main --configure
[[ "$(cat "$FIXTURE/actions")" == $'docker reset-password\ndocker configure' ]]
# Empty folders are neither installed panels nor recreated by deletion.
rm -rf "$INSTALL_DIR" "$FIREWALL_UI_DOCKER_DIR"
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$STATE_DIR" "$FIREWALL_UI_DOCKER_DIR"
installer_detect_installations
[[ "$NATIVE_INSTALLED" == 0 && "$COMPOSE_INSTALLED" == 0 ]]
main --uninstall
[[ ! -d "$INSTALL_DIR" && ! -d "$CONFIG_DIR" && ! -d "$STATE_DIR" && ! -d "$FIREWALL_UI_DOCKER_DIR" ]]

# Settings/service submenus support back and preserve the numeric variant choice.
mkdir -p "$INSTALL_DIR"; touch "$INSTALL_DIR/firewall-ui"
INSTALL_INTERACTIVE=1
for route in '2 2 credentials' '7 1 start' '7 2 stop' '7 3 restart'; do
 read -r section item expected <<< "$route"
 printf '%s\n%s\n' "$section" "$item" > "$FIXTURE/answer"; exec 3<>"$FIXTURE/answer"
 select_installer_action > /dev/null
 [[ "$INSTALL_ACTION" == "$expected" ]]
done
printf '2\n0\n7\n0\n0\n' > "$FIXTURE/answer"; exec 3<>"$FIXTURE/answer"
select_installer_action > /dev/null
[[ "$INSTALL_ACTION" == exit ]]
# A rejected deletion and a failed transaction both return to the main menu.
(
 installer_uninstall_all() { echo 'PURGE SHOULD NOT RUN'; return 1; }
 printf '4\nn\n\n0\n' > "$FIXTURE/answer"; exec 3<>"$FIXTURE/answer"
 installer_menu_loop
) > "$FIXTURE/cancelled" 2>&1
[[ "$(cat "$FIXTURE/cancelled")" == *'Удаление отменено.'* ]]
[[ "$(cat "$FIXTURE/cancelled")" != *'PURGE SHOULD NOT RUN'* ]]
(
 installer_native_install() { false; echo 'ERREXIT WAS DISABLED'; }
 printf '1\n1\n\n0\n' > "$FIXTURE/answer"; exec 3<>"$FIXTURE/answer"
 installer_menu_loop
) > "$FIXTURE/failed-menu" 2>&1
[[ "$(cat "$FIXTURE/failed-menu")" == *'Действие завершилось ошибкой'* ]]
[[ "$(cat "$FIXTURE/failed-menu")" != *'ERREXIT WAS DISABLED'* ]]
[[ "$(awk '/Установка и обслуживание/ {n++} END {print n}' "$FIXTURE/failed-menu")" == 2 ]]
# Addresses format IPv6 correctly, and no credential file is displayed.
mkdir -p "$CONFIG_DIR"
printf '{"publicHost":"2001:db8::1","listenPort":8443,"tlsCert":"/etc/firewall-ui/cert.pem"}\n' > "$CONFIG_DIR/config.json"
printf 'SECRET-PASSWORD' > "$CONFIG_DIR/environment"
installer_connection_info > "$FIXTURE/connection"
[[ "$(cat "$FIXTURE/connection")" == *'https://[2001:db8::1]:8443'* ]]
[[ "$(cat "$FIXTURE/connection")" != *'SECRET-PASSWORD'* ]]
exec 3>&-
echo 'Unified menu navigation, safe deletion, strict failure isolation and addresses passed'
source "$TASK_ROOT/deploy/firewall-ui"
require_root() { :; }
BIN="$FIXTURE/binary"; ENV_FILE="$FIXTURE/environment"
printf '#!/bin/sh\nexit 0\n' > "$BIN"; chmod +x "$BIN"
printf 'FIREWALL_UI_USERNAME="custom-user"\nFIREWALL_UI_PASSWORD="old"\nOTHER_SETTING="keep"\n' > "$ENV_FILE"
systemctl() { printf '%s\n' "$*" >> "$FIXTURE/systemctl"; }
FIREWALL_UI_PASSWORD=1
reset_password
[[ "$(cat "$ENV_FILE")" == *'FIREWALL_UI_USERNAME="custom-user"'* && "$(cat "$ENV_FILE")" == *'FIREWALL_UI_PASSWORD="1"'* && "$(cat "$ENV_FILE")" == *'OTHER_SETTING="keep"'* ]]
[[ "$(stat -c %a "$ENV_FILE")" == 600 ]]
[[ "$(cat "$FIXTURE/systemctl")" == 'restart firewall-ui.service' ]]
printf 'Installer menu, reset/purge dispatch, short password and username preservation passed\n'

# Blank username keeps the current account; unrelated environment settings survive.
FIREWALL_UI_NONINTERACTIVE=0
change_credentials <<'INPUT'

2
INPUT
[[ "$(cat "$ENV_FILE")" == *'FIREWALL_UI_USERNAME="custom-user"'* ]]
[[ "$(cat "$ENV_FILE")" == *'FIREWALL_UI_PASSWORD="2"'* && "$(cat "$ENV_FILE")" == *'OTHER_SETTING="keep"'* ]]
