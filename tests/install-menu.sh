#!/usr/bin/env bash
set -Eeuo pipefail
TASK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE="$(mktemp -d)"
trap 'rm -rf -- "$FIXTURE"' EXIT
source "$TASK_ROOT/install.sh"
INSTALL_INTERACTIVE=1
for selection in '1 install' '2 configure' '3 reset-password' '4 uninstall' '0 exit'; do
  read -r answer expected <<< "$selection"
  printf '%s\n' "$answer" > "$FIXTURE/answer"
  exec 3<>"$FIXTURE/answer"
  select_installer_action
  [[ "$INSTALL_ACTION" == "$expected" ]]
  exec 3>&-
done
# Reset and purge dispatch before package installation, UFW detection or updates.
FIREWALL_UI_NONINTERACTIVE=1
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
[[ "$(cat "$FIXTURE/actions")" == $'reset-password\nuninstall --purge' ]]
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
