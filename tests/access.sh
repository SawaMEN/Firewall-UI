#!/usr/bin/env bash
set -Eeuo pipefail
TASK_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$TASK_ROOT/install.sh"
# Public defaults are bounded, validated, and never substitute a private address.
(
 curl() { printf '%s' "${MOCK_PUBLIC_IP:-8.8.4.4}"; }
 hostname() { printf '%s' "${MOCK_HOSTNAME:-panel.example.com}"; }
 timeout() { shift; "$@"; }
 getent() { printf '%s STREAM panel.example.com\n' "${MOCK_DNS_IP:-8.8.4.4}"; }
 ip() { printf '2: eth0 inet 9.9.9.9/24 scope global eth0\n'; }
 [[ "$(installer_suggest_host ip)" == 8.8.4.4 ]]
 [[ "$(installer_suggest_host domain)" == panel.example.com ]]
 MOCK_DNS_IP=1.1.1.1
 [[ -z "$(installer_suggest_host domain)" ]]
 MOCK_HOSTNAME=server.local
 [[ -z "$(installer_suggest_host domain)" ]]
 MOCK_PUBLIC_IP='not an IP'
 [[ "$(installer_suggest_host ip)" == 9.9.9.9 ]]
 curl() { return 1; }; ip() { return 1; }
 [[ -z "$(installer_suggest_host ip)" ]]
 for address in 127.0.0.1 10.0.0.1 172.16.0.1 192.168.0.1 100.64.0.1 999.1.1.1 2001:db8::1 fe80::1; do
   if installer_public_ip "$address"; then echo "Invalid public default: $address"; exit 1; fi
 done
 installer_public_ip 2606:4700:4700::1111
)
# Other fixtures supply their own address and do not access external discovery.
installer_suggest_host() { :; }
FIXTURE="$(mktemp -d)"
trap 'rm -rf -- "$FIXTURE"' EXIT
CONFIG_DIR="$FIXTURE/config"; STATE_DIR="$FIXTURE/state"; TEMP_DIR="$FIXTURE/temp"
mkdir -p "$CONFIG_DIR" "$STATE_DIR" "$TEMP_DIR"
UPDATE_CHANNEL=stable
FIREWALL_UI_NONINTERACTIVE=1; FIREWALL_UI_PASSWORD=1
(
 installer_suggest_host() { printf '8.8.4.4'; }
 INSTALL_INTERACTIVE=1
 FIREWALL_UI_ACCESS_MODE=ip; FIREWALL_UI_TLS_MODE=selfsigned
 printf '\n\nN\n' > "$FIXTURE/default-answers"; exec 3<>"$FIXTURE/default-answers"
 choose_access
 [[ "$PUBLIC_HOST" == 8.8.4.4 && "$OPEN_PORTS" == 0 ]]
 SAVED_PUBLIC_HOST=9.9.9.9
 installer_suggest_host() { echo 'Unexpected discovery'; return 1; }
 exec 3<>"$FIXTURE/default-answers"
 choose_access
 [[ "$PUBLIC_HOST" == 9.9.9.9 ]]
)
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
FIREWALL_UI_NONINTERACTIVE=0
change_credentials <<'INPUT'
admin
1
INPUT
[[ "$(cat "$ENV_FILE")" == *'FIREWALL_UI_PASSWORD="1"'* ]]
printf 'Short password, Russian wizard, domain/IP SANs, ACME flags and URLs passed\n'
