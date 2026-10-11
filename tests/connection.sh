#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE="$(mktemp -d)"; trap 'rm -rf -- "$FIXTURE"' EXIT
source "$ROOT/install.sh"
export FIREWALL_UI_DOCKER_DIR="$FIXTURE/docker" FIREWALL_UI_CONFIG_DIR="$FIXTURE/config"
CONFIG_DIR="$FIREWALL_UI_CONFIG_DIR"; INSTALL_DIR="$FIXTURE/native"; SERVICE_FILE="$FIXTURE/service"
mkdir -p "$CONFIG_DIR" "$FIREWALL_UI_DOCKER_DIR/source"
printf 'FIREWALL_UI_DOCKER_PORT=8088\nFIREWALL_UI_PUBLIC_HOST=old.example\nFIREWALL_UI_TLS_CERT=old.pem\n' > "$FIREWALL_UI_DOCKER_DIR/docker.env"
printf '{"listenHost":"127.0.0.1","listenPort":9443,"publicHost":"new.example"}\n' > "$CONFIG_DIR/config.json"
output="$(installer_connection_info)"
[[ "$output" == *'http://new.example:9443/'* && "$output" == *'Доступ только с сервера'* && "$output" != *old.example* ]]
curl() { printf '%s\n' "$*" > "$FIXTURE/request"; printf '%s' "${MOCK_BODY:-}"; return "${MOCK_CURL_RESULT:-0}"; }
MOCK_BODY=$'{"success":true,"obj":{"version":"1.3.5"}}\n200'
installer_panel_ready "$CONFIG_DIR/config.json"
[[ "$(cat "$FIXTURE/request")" == *'http://127.0.0.1:9443/api/health'* && "$(cat "$FIXTURE/request")" == *'--noproxy *'* ]]
MOCK_BODY=$'access denied\n\n403'; installer_panel_ready "$CONFIG_DIR/config.json"
MOCK_BODY=$'<html>other service</html>\n200'
if installer_panel_ready "$CONFIG_DIR/config.json"; then exit 1; fi
MOCK_CURL_RESULT=7
systemctl() { return 1; }
docker() { if [[ "$*" == *'--format {{.Names}}'* ]]; then echo firewall-ui; fi; }
[[ "$(installer_status)" == *'контейнер запущен, веб-панель не отвечает'* ]]
MOCK_CURL_RESULT=0; MOCK_BODY=$'{"success":true,"obj":{"version":"1.3.5"}}\n200'
[[ "$(installer_status)" == *'веб-панель отвечает локально'* ]]
printf '{"listenHost":"::","listenPort":8443,"tlsCert":"cert.pem","publicHost":"2001:db8::2"}\n' > "$CONFIG_DIR/config.json"
installer_panel_ready "$CONFIG_DIR/config.json"
[[ "$(cat "$FIXTURE/request")" == *'https://[::1]:8443/api/health'* ]]
[[ "$(installer_connection_info)" == *'https://[2001:db8::2]:8443/'* ]]
source "$ROOT/deploy/firewall-ui-docker"
DOCKER_DIR="$FIREWALL_UI_DOCKER_DIR"; DOCKER_CONFIG_DIR="$CONFIG_DIR"
cp "$ROOT/install.sh" "$DOCKER_DIR/source/install.sh"
docker_compose() { [[ "$*" != 'ps -q firewall-ui' ]] || echo fixture; }
docker() { echo 'true false'; }
sleep() { :; }
MOCK_CURL_RESULT=7
if docker_wait_for_service; then echo 'Container running without HTTP was accepted'; exit 1; fi
MOCK_CURL_RESULT=0; docker_wait_for_service
printf 'Actual Docker addresses, loopback warnings, IPv6/TLS and HTTP readiness passed\n'
