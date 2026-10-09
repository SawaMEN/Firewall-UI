#!/usr/bin/env bash
set -Eeuo pipefail
TASK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$TASK_ROOT/install.sh"
FIXTURE="$(mktemp -d)"
trap 'rm -rf -- "$FIXTURE"' EXIT
CONFIG_DIR="$FIXTURE/config"; STATE_DIR="$FIXTURE/state"; TEMP_DIR="$FIXTURE/temp"
mkdir -p "$CONFIG_DIR" "$STATE_DIR" "$TEMP_DIR"
UPDATE_CHANNEL=stable
FIREWALL_UI_NONINTERACTIVE=1; FIREWALL_UI_PASSWORD=1
# A one-character password is persisted, not rejected or substituted.
create_settings
[[ "$(cat "$CONFIG_DIR/environment")" == *'FIREWALL_UI_PASSWORD="1"'* ]]
# Interactive domain selection, certificate choice and one-character password.
rm -f "$CONFIG_DIR/config.json" "$CONFIG_DIR/environment"
unset FIREWALL_UI_PASSWORD
INSTALL_INTERACTIVE=1
printf '2\npanel.example.com\n3\n8443\nn\nadmin\n1\n' > "$FIXTURE/answers"
exec 3<>"$FIXTURE/answers"
create_settings
exec 3>&-
[[ "$PUBLIC_HOST" == panel.example.com && "$PANEL_HOST" == 0.0.0.0 && "$PANEL_PORT" == 8443 && "$OPEN_PORTS" == 0 ]]
[[ "$(cat "$CONFIG_DIR/environment")" == *'FIREWALL_UI_PASSWORD="1"'* ]]
openssl x509 -in "$TLS_CERT" -noout -checkhost panel.example.com
[[ "$(stat -c %a "$TLS_KEY")" == 600 ]]
[[ "$(show_panel_url)" == 'Адрес панели: https://panel.example.com:8443/' ]]
# IPv6 certificate SAN and URL brackets.
printf '2\npanel.example.com\n3\n8443\nY\n' > "$FIXTURE/answers"
exec 3<>"$FIXTURE/answers"
choose_access
exec 3>&-
[[ "$OPEN_PORTS" == 1 ]]
INSTALL_INTERACTIVE=0; FIREWALL_UI_ACCESS_MODE=ip; FIREWALL_UI_PUBLIC_HOST=2001:db8::1
FIREWALL_UI_TLS_MODE=selfsigned; FIREWALL_UI_PORT=9443
choose_access; prepare_tls
openssl x509 -in "$TLS_CERT" -noout -checkip 2001:db8::1
[[ "$PANEL_HOST" == :: && "$(show_panel_url)" == 'Адрес панели: https://[2001:db8::1]:9443/' ]]
# ACME arguments are tested with a stub; no account/certificate is requested.
certbot() {
  if [[ "$1" == --help ]]; then echo '--ip-address --preferred-profile'; return; fi
  printf '%s\n' "$@" > "$FIXTURE/certbot-args"
  mkdir -p "$CONFIG_DIR/acme/live/firewall-ui"
  cp "$TLS_CERT" "$CONFIG_DIR/acme/live/firewall-ui/fullchain.pem"
  cp "$TLS_KEY" "$CONFIG_DIR/acme/live/firewall-ui/privkey.pem"
}
TLS_MODE=letsencrypt; OPEN_PORTS=0
prepare_tls
[[ "$(cat "$FIXTURE/certbot-args")" == *$'--ip-address\n2001:db8::1\n--preferred-profile\nshortlived'* ]]
[[ "$ACME_SETUP" == 1 ]]
# Old Certbot must fail clearly instead of claiming a working IP certificate.
certbot() { echo 'old certbot without IP support'; }
if (prepare_tls); then echo 'Accepted old Certbot for an IP certificate'; exit 1; fi
# Existing certificate paths are required to be readable absolute files.
TLS_MODE=existing; TLS_CERT=relative.pem; TLS_KEY=missing.pem
if (prepare_tls); then echo 'Accepted invalid certificate paths'; exit 1; fi
# Console credential changes accept the same simple password.
source "$TASK_ROOT/deploy/firewall-ui"
ENV_FILE="$FIXTURE/credentials"
require_root() { :; }
systemctl() { :; }
change_credentials <<'INPUT'
admin
1
INPUT
[[ "$(cat "$ENV_FILE")" == *'FIREWALL_UI_PASSWORD="1"'* ]]
printf 'Short password, Russian wizard, domain/IP SANs, ACME flags and URLs passed\n'
