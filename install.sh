#!/usr/bin/env bash
set -Eeuo pipefail

REPO="SawaMEN/Firewall-UI"
RAW_BASE="https://raw.githubusercontent.com/${REPO}/main"
INSTALL_DIR="/usr/local/firewall-ui"
CONFIG_DIR="/etc/firewall-ui"
STATE_DIR="/var/lib/firewall-ui"
SERVICE_FILE="/etc/systemd/system/firewall-ui.service"
MANAGER="/usr/local/bin/firewall-ui"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd || true)"
TEMP_DIR=""
REPLACED=0
SUCCEEDED=0
HAD_BINARY=0
WAS_ACTIVE=0
WAS_ENABLED=0

pkg_install() {
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
  elif command -v dnf >/dev/null 2>&1; then dnf install -y "$@"
  elif command -v yum >/dev/null 2>&1; then yum install -y "$@"
  elif command -v pacman >/dev/null 2>&1; then pacman -S --needed --noconfirm "$@"
  elif command -v zypper >/dev/null 2>&1; then zypper --non-interactive install "$@"
  else echo 'Нужен пакетный менеджер apt/dnf/yum/pacman/zypper.' >&2; return 1; fi
}

detect_firewall() {
  local first="" backend binary
  for backend in ufw firewalld nftables iptables; do
    case "$backend" in ufw) binary=ufw;; firewalld) binary=firewall-cmd;; nftables) binary=nft;; iptables) binary=iptables;; esac
    command -v "$binary" >/dev/null 2>&1 || continue
    [[ -n "$first" ]] || first="$backend"
    case "$backend" in
      ufw) if LC_ALL=C ufw status 2>/dev/null | grep -qi '^Status: active'; then echo ufw; return; fi;;
      firewalld) if firewall-cmd --state 2>/dev/null | grep -qx running; then echo firewalld; return; fi;;
      nftables) if [[ -n "$(nft list ruleset 2>/dev/null)" ]]; then echo nftables; return; fi;;
      iptables) if iptables -S 2>/dev/null | grep -Eq '^-A |^-P .* (DROP|REJECT)$'; then echo iptables; return; fi;;
    esac
  done
  echo "${first:-none}"
}

check_system() {
  [[ "$(uname -s)" == Linux ]] || { echo 'Firewall-UI поддерживает только Linux.' >&2; return 1; }
  case "$(uname -m)" in x86_64|amd64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; *) echo 'Архитектура процессора не поддерживается.' >&2; return 1;; esac
  command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]] || { echo 'Нужен запущенный systemd.' >&2; return 1; }
  echo "Linux/$ARCH; обнаружен файрволл: $(detect_firewall)"
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 "$1" | awk '{print $NF}'
  else echo 'Нужен sha256sum или openssl.' >&2; return 1; fi
}

fetch_repo_file() {
  local path="$1" destination="$2"
  if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/$path" && ( "$path" != install.sh || -f "$SCRIPT_DIR/Dockerfile" ) ]]; then
    install -m 0644 "$SCRIPT_DIR/$path" "$destination"
  else curl -fLsS --retry 3 --connect-timeout 15 "${RAW_BASE}/$path" -o "$destination"; fi
}

build_from_source() {
  command -v go >/dev/null && command -v npm >/dev/null && command -v tar >/dev/null || {
    echo 'Готовый релиз недоступен. Дождитесь сборки GitHub Actions или задайте FIREWALL_UI_BINARY.' >&2; return 1;
  }
  local directory="$TEMP_DIR/source"
  mkdir -p "$directory"
  curl -fLsS --retry 3 "https://github.com/${REPO}/archive/refs/heads/main.tar.gz" -o "$TEMP_DIR/source.tar.gz"
  tar -xzf "$TEMP_DIR/source.tar.gz" --strip-components=1 -C "$directory"
  (cd "$directory/frontend" && npm ci --ignore-scripts && npm run build)
  (cd "$directory" && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o "$TEMP_DIR/binary" ./cmd/firewall-ui)
}

download_binary() {
  if [[ -n "${FIREWALL_UI_BINARY:-}" ]]; then
    install -m 0755 "$FIREWALL_UI_BINARY" "$TEMP_DIR/binary"
    if [[ -n "${FIREWALL_UI_SHA256:-}" ]]; then
      [[ "$(sha256_file "$TEMP_DIR/binary")" == "$FIREWALL_UI_SHA256" ]] || { echo 'Контрольная сумма локального бинарника не совпадает.' >&2; return 1; }
    fi
    return
  fi
  local manifest_url channel block url expected actual
  channel="$UPDATE_CHANNEL"
  if [[ "$channel" == dev ]]; then manifest_url="https://github.com/${REPO}/releases/download/dev/update.json"
  else manifest_url="https://github.com/${REPO}/releases/latest/download/update.json"; fi
  if ! curl -fLsS --retry 3 --connect-timeout 15 "$manifest_url" -o "$TEMP_DIR/update.json"; then
    echo 'Метаданные релиза недоступны. Пробуем собрать из исходников...'
    build_from_source
    return
  fi
  block="$(sed -n "/\"$ARCH\"[[:space:]]*:/,/^[[:space:]]*}/p" "$TEMP_DIR/update.json")"
  url="$(printf '%s\n' "$block" | sed -n 's/.*"url":[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
  expected="$(printf '%s\n' "$block" | sed -n 's/.*"sha256":[[:space:]]*"\([0-9A-Fa-f]*\)".*/\1/p' | head -n 1)"
  [[ "$url" =~ ^https://github.com/${REPO}/releases/download/[A-Za-z0-9._-]+/firewall-ui-linux-${ARCH}$ && "$expected" =~ ^[0-9A-Fa-f]{64}$ ]] || {
    echo 'Неверные метаданные релиза.' >&2; return 1;
  }
  if [[ -n "${FIREWALL_UI_DOWNLOAD_URL:-}" && "$FIREWALL_UI_DOWNLOAD_URL" != "$url" ]]; then
    echo 'Для своего бинарника используйте FIREWALL_UI_BINARY и FIREWALL_UI_SHA256.' >&2; return 1
  fi
  curl -fLsS --retry 3 --connect-timeout 15 "$url" -o "$TEMP_DIR/binary"
  actual="$(sha256_file "$TEMP_DIR/binary")"
  [[ "${actual,,}" == "${expected,,}" ]] || { echo 'SHA-256 бинарника релиза не совпадает.' >&2; return 1; }
  chmod 0755 "$TEMP_DIR/binary"
}

escape_env_value() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

# The installer reads from /dev/tty even when invoked through curl/process substitution.
ask() {
  local name="$1" prompt="$2" fallback="$3" reply=''
  if [[ "${INSTALL_INTERACTIVE:-0}" == 1 ]]; then
    read -r -p "$prompt [$fallback]: " reply <&3 || return 1
  fi
  printf -v "$name" '%s' "${reply:-$fallback}"
}

json_text() {
  [[ "$1" != *$'\n'* && "$1" != *$'\r'* ]] || { echo 'Перевод строки в параметре не поддерживается.' >&2; return 1; }
  escape_env_value "$1"
}

choose_access() {
  ACCESS_MODE=local
  if [[ -n "${SAVED_PUBLIC_HOST:-}" ]]; then
    ACCESS_MODE=domain
    [[ "$SAVED_PUBLIC_HOST" != *:* && ! "$SAVED_PUBLIC_HOST" =~ ^[0-9.]+$ ]] || ACCESS_MODE=ip
  fi
  ACCESS_MODE="${FIREWALL_UI_ACCESS_MODE:-$ACCESS_MODE}"
  if [[ "${INSTALL_INTERACTIVE:-0}" == 1 && -z "${FIREWALL_UI_ACCESS_MODE:-}" ]]; then
    echo 'Как подключаться к Firewall-UI?'
    echo '1) Только локально / через SSH-туннель'
    echo '2) Из интернета по домену, с HTTPS'
    echo '3) Из интернета по IP, с HTTPS'
    local choice
    local default=1
    case "$ACCESS_MODE" in domain) default=2;; ip) default=3;; esac
    ask choice 'Выберите режим' "$default"
    case "$choice" in 1) ACCESS_MODE=local;; 2) ACCESS_MODE=domain;; 3) ACCESS_MODE=ip;; *) echo 'Неизвестный режим доступа.' >&2; return 1;; esac
  fi
  PANEL_HOST="${FIREWALL_UI_LISTEN_HOST:-127.0.0.1}"
  PANEL_PORT="${FIREWALL_UI_PORT:-${SAVED_PANEL_PORT:-8088}}"
  PUBLIC_HOST="${FIREWALL_UI_PUBLIC_HOST:-${SAVED_PUBLIC_HOST:-}}"
  TLS_CERT="${FIREWALL_UI_TLS_CERT:-${SAVED_TLS_CERT:-}}"; TLS_KEY="${FIREWALL_UI_TLS_KEY:-${SAVED_TLS_KEY:-}}"
  TLS_MODE="${FIREWALL_UI_TLS_MODE:-}"
  case "$ACCESS_MODE" in
    local)
      PUBLIC_HOST="${FIREWALL_UI_PUBLIC_HOST:-}"
      TLS_CERT="${FIREWALL_UI_TLS_CERT:-}"; TLS_KEY="${FIREWALL_UI_TLS_KEY:-}"
      [[ -z "$TLS_MODE" || "$TLS_MODE" == existing ]] || { echo 'Для выпуска сертификата выберите режим домена или IP.' >&2; return 1; }
      ;;
    domain|ip)
      ask PUBLIC_HOST 'Домен или IP (без https:// и порта)' "$PUBLIC_HOST"
      [[ -n "$PUBLIC_HOST" && "$PUBLIC_HOST" != *[!a-zA-Z0-9.:-]* ]] || { echo 'Укажите домен или IP без схемы, пробелов и порта.' >&2; return 1; }
      [[ "$ACCESS_MODE" != ip || "$PUBLIC_HOST" == *:* || "$PUBLIC_HOST" =~ ^[0-9.]+$ ]] || { echo 'В режиме IP нужен IP-адрес.' >&2; return 1; }
      [[ "$ACCESS_MODE" != domain || ( "$PUBLIC_HOST" != *:* && ! "$PUBLIC_HOST" =~ ^[0-9.]+$ ) ]] || { echo 'В режиме домена нужно доменное имя.' >&2; return 1; }
      PANEL_HOST="${FIREWALL_UI_LISTEN_HOST:-0.0.0.0}"
      [[ "$PUBLIC_HOST" != *:* || -n "${FIREWALL_UI_LISTEN_HOST:-}" ]] || PANEL_HOST='::'
      [[ "$PANEL_HOST" != 127.0.0.1 && "$PANEL_HOST" != ::1 && "$PANEL_HOST" != localhost ]] || { echo 'Для внешнего доступа выберите внешний интерфейс.' >&2; return 1; }
      if [[ -z "$TLS_MODE" ]]; then
        if [[ "${INSTALL_INTERACTIVE:-0}" == 1 ]]; then
          echo 'Сертификат для HTTPS:'
          echo '1) Готовый сертификат и ключ PEM'
          echo '2) Получить доверенный сертификат Let’s Encrypt (домен или публичный IP)'
          echo '3) Создать самоподписанный (браузер потребует подтверждения доверия)'
          local choice
          local default_cert=2
          [[ -z "$TLS_CERT" || -z "$TLS_KEY" ]] || default_cert=1
          ask choice 'Выберите сертификат' "$default_cert"
          case "$choice" in 1) TLS_MODE=existing;; 2) TLS_MODE=letsencrypt;; 3) TLS_MODE=selfsigned;; *) echo 'Неизвестный вариант сертификата.' >&2; return 1;; esac
        elif [[ -n "$TLS_CERT" && -n "$TLS_KEY" ]]; then TLS_MODE=existing
        else echo 'Для внешнего доступа задайте FIREWALL_UI_TLS_MODE: existing, letsencrypt или selfsigned.' >&2; return 1; fi
      fi
      ;;
    *) echo 'Режим доступа: local, domain или ip.' >&2; return 1;;
  esac
  ask PANEL_PORT 'TCP-порт панели' "$PANEL_PORT"
  [[ "$PANEL_PORT" =~ ^[0-9]{1,5}$ ]] && ((10#$PANEL_PORT>=1 && 10#$PANEL_PORT<=65535)) || { echo 'Неверный порт панели.' >&2; return 1; }
  [[ "$PANEL_HOST" == localhost || "$PANEL_HOST" =~ ^[0-9a-fA-F:.]+$ ]] || { echo 'Неверный адрес интерфейса.' >&2; return 1; }
  OPEN_PORTS="${FIREWALL_UI_OPEN_PORTS:-0}"
  if [[ "$ACCESS_MODE" != local && "${INSTALL_INTERACTIVE:-0}" == 1 && -z "${FIREWALL_UI_OPEN_PORTS:-}" ]]; then
    local answer
    ask answer 'Разрешить входящий TCP-порт панели (и 80 для Let’s Encrypt) в UFW/firewalld? (y/n)' y
    case "${answer,,}" in
      y|yes) OPEN_PORTS=1;;
      n|no) OPEN_PORTS=0;;
      *) echo 'Введите y или n.' >&2; return 1;;
    esac
  fi
  if [[ "$TLS_MODE" == existing ]]; then
    ask TLS_CERT 'Абсолютный путь к сертификату PEM' "$TLS_CERT"
    ask TLS_KEY 'Абсолютный путь к приватному ключу PEM' "$TLS_KEY"
  fi
}

write_new_config() {
  local target="$1" secure=false value
  for value in "$PUBLIC_HOST" "$PANEL_HOST" "$TLS_CERT" "$TLS_KEY" "$STATE_DIR"; do json_text "$value" >/dev/null || return 1; done
  [[ -z "$TLS_CERT" ]] || secure=true
  cat > "$target" <<JSON
{
  "publicHost": "$(json_text "$PUBLIC_HOST")",
  "listenHost": "$(json_text "$PANEL_HOST")",
  "listenPort": $((10#$PANEL_PORT)),
  "externalPort": 0,
  "secureCookies": $secure,
  "tlsCert": "$(json_text "$TLS_CERT")",
  "tlsKey": "$(json_text "$TLS_KEY")",
  "statePath": "$(json_text "$STATE_DIR")/state.json",
  "updateChannel": "$UPDATE_CHANNEL",
  "rollbackSeconds": 45,
  "portScanInterval": 2
}
JSON
  chmod 0600 "$target"
}

allow_access_port() {
  [[ "${OPEN_PORTS:-0}" == 1 ]] || return 0
  local port="$1" backend zone layer; backend="$(detect_firewall)"
  case "$backend" in
    ufw)
      local added line found=0
      added="$(ufw show added)" || return 1
      while IFS= read -r line; do
        # UFW updates the comment of duplicate rules. Do not take ownership of
        # an existing administrator allowance by replacing its comment.
        line="${line%% comment *}"
        if [[ "$line" == "ufw allow $port/tcp" || "$line" == "ufw allow proto tcp to any port $port" || "$line" == "ufw allow to any port $port proto tcp" ]]; then found=1; fi
      done <<< "$added"
      if (( !found )); then ufw allow "$port/tcp" comment 'Firewall-UI access'; fi;;
    firewalld)
      zone="$(firewall-cmd --get-default-zone)"
      [[ "$zone" =~ ^[A-Za-z0-9_-]+$ ]] || return 1
      install -d -m 0700 "$STATE_DIR"
      touch "$STATE_DIR/access-rules"; chmod 0600 "$STATE_DIR/access-rules"
      for layer in runtime permanent; do
        local -a args=(--zone="$zone")
        [[ "$layer" != permanent ]] || args+=(--permanent)
        if ! firewall-cmd "${args[@]}" --query-port="$port/tcp" >/dev/null 2>&1; then
          firewall-cmd "${args[@]}" --add-port="$port/tcp" || return 1
          printf '%s %s %s/tcp\n' "$layer" "$zone" "$port" >> "$STATE_DIR/access-rules"
        fi
      done;;
    nftables|iptables) echo "В существующем $backend разрешите входящий TCP $port вручную; чужой ruleset не изменяется.";;
  esac
}

prepare_tls() {
  case "$TLS_MODE" in
    '') [[ "$ACCESS_MODE" == local ]] || return 1;;
    existing)
      [[ "$TLS_CERT" == /* && "$TLS_KEY" == /* && -r "$TLS_CERT" && -r "$TLS_KEY" ]] || { echo 'Нужны доступные сертификат и ключ с абсолютными путями.' >&2; return 1; }
      ;;
    selfsigned)
      command -v openssl >/dev/null || pkg_install openssl
      install -d -m 0700 "$CONFIG_DIR/tls"
      local cert_dir; cert_dir="$(mktemp -d "$CONFIG_DIR/tls/cert-XXXXXX")"
      local san="DNS:$PUBLIC_HOST"
      [[ "$ACCESS_MODE" != ip ]] || san="IP:$PUBLIC_HOST"
      if ! openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 365 -subj '/CN=Firewall-UI' -addext "subjectAltName=$san" -keyout "$cert_dir/privkey.pem" -out "$cert_dir/fullchain.pem" 2>"$cert_dir/generation.log"; then cat "$cert_dir/generation.log" >&2; return 1; fi
      rm -f "$cert_dir/generation.log"
      chmod 0600 "$cert_dir/privkey.pem"
      TLS_CERT="$cert_dir/fullchain.pem"; TLS_KEY="$cert_dir/privkey.pem"
      echo 'Самоподписанный сертификат создан. Браузер не доверяет ему автоматически.'
      ;;
    letsencrypt)
      [[ "$PANEL_PORT" != 80 ]] || { echo 'Для Let’s Encrypt порт панели должен отличаться от 80.' >&2; return 1; }
      echo 'Для выпуска и продления нужен доступ с интернета к TCP 80. Домен должен указывать на этот сервер.'
      echo 'Если порт 80 занят веб-сервером, используйте его готовые PEM-файлы или выпустите сертификат отдельно.'
      command -v certbot >/dev/null || pkg_install certbot
      local email="${FIREWALL_UI_ACME_EMAIL:-}" help
      ask email 'Email для Let’s Encrypt (необязательно)' "$email"
      local args=(certonly --standalone --non-interactive --agree-tos --cert-name firewall-ui --config-dir "$CONFIG_DIR/acme" --work-dir "$STATE_DIR/acme" --logs-dir "$STATE_DIR/acme-logs")
      if [[ -n "$email" ]]; then args+=(--email "$email"); else args+=(--register-unsafely-without-email); fi
      if [[ "$ACCESS_MODE" == ip ]]; then
        help="$(certbot --help all)"
        [[ "$help" == *--ip-address* && "$help" == *--preferred-profile* ]] || { echo 'Для сертификата IP нужен Certbot 5.3 или новее. Обновите Certbot или выберите готовый/самоподписанный сертификат.' >&2; return 1; }
        args+=(--ip-address "$PUBLIC_HOST" --preferred-profile shortlived)
      else args+=(-d "$PUBLIC_HOST"); fi
      allow_access_port 80
      certbot "${args[@]}"
      TLS_CERT="$CONFIG_DIR/acme/live/firewall-ui/fullchain.pem"; TLS_KEY="$CONFIG_DIR/acme/live/firewall-ui/privkey.pem"
      [[ -r "$TLS_CERT" && -r "$TLS_KEY" ]] || { echo 'Certbot не создал сертификат и ключ.' >&2; return 1; }
      ACME_SETUP=1
      ;;
    *) echo 'Сертификат: existing, letsencrypt или selfsigned.' >&2; return 1;;
  esac
}

setup_renewal() {
  if [[ "${ACME_SETUP:-0}" != 1 ]]; then
    if [[ "${CONFIG_CHANGED:-0}" == 1 ]]; then systemctl disable --now firewall-ui-cert-renew.timer >/dev/null 2>&1 || true; fi
    return 0
  fi
  fetch_repo_file deploy/firewall-ui-cert-renew.service "$TEMP_DIR/renew.service"
  fetch_repo_file deploy/firewall-ui-cert-renew.timer "$TEMP_DIR/renew.timer"
  install -m 0644 "$TEMP_DIR/renew.service" /etc/systemd/system/firewall-ui-cert-renew.service
  install -m 0644 "$TEMP_DIR/renew.timer" /etc/systemd/system/firewall-ui-cert-renew.timer
  systemctl daemon-reload
  systemctl enable --now firewall-ui-cert-renew.timer
  echo 'Автоматическое продление сертификата настроено (проверка каждые 12 часов).'
}

show_panel_url() {
  local scheme=http host="${PUBLIC_HOST:-$PANEL_HOST}"
  [[ -z "${TLS_CERT:-}" ]] || scheme=https
  [[ "$host" != 0.0.0.0 && "$host" != :: ]] || host='<IP-сервера>'
  [[ "$host" != *:* ]] || host="[$host]"
  echo "Адрес панели: ${scheme}://${host}:${PANEL_PORT}/"
}

create_settings() {
  CONFIG_FILE="$CONFIG_DIR/config.json"
  if [[ -f "$CONFIG_FILE" ]]; then
    SAVED_PANEL_PORT="$(sed -n 's/.*"listenPort":[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$CONFIG_FILE" | head -n 1)"
    SAVED_PUBLIC_HOST="$(sed -n 's/.*"publicHost":[[:space:]]*"\([^" ]*\)".*/\1/p' "$CONFIG_FILE" | head -n 1)"
    SAVED_TLS_CERT="$(sed -n 's/.*"tlsCert":[[:space:]]*"\([^" ]*\)".*/\1/p' "$CONFIG_FILE" | head -n 1)"
    SAVED_TLS_KEY="$(sed -n 's/.*"tlsKey":[[:space:]]*"\([^" ]*\)".*/\1/p' "$CONFIG_FILE" | head -n 1)"
  fi
  local reconfigure="${FIREWALL_UI_RECONFIGURE:-0}" candidate
  if [[ -f "$CONFIG_FILE" && "$reconfigure" != 1 && "${INSTALL_INTERACTIVE:-0}" == 1 ]]; then
    local answer
    ask answer 'Настройки уже есть. Изменить способ доступа? (y/n)' n
    case "${answer,,}" in
      y|yes) reconfigure=1;;
      n|no) :;;
      *) echo 'Введите y или n.' >&2; return 1;;
    esac
  fi
  if [[ ! -f "$CONFIG_FILE" || "$reconfigure" == 1 ]]; then
    choose_access
    candidate="$(mktemp "$CONFIG_DIR/.access-XXXXXX")"
    ACCESS_CANDIDATE="$candidate"
    # Validate the address before contacting a CA or creating a certificate.
    local requested_cert="$TLS_CERT" requested_key="$TLS_KEY"
    TLS_CERT=''; TLS_KEY=''; write_new_config "$candidate"
    if [[ -x "${TEMP_DIR:-}/binary" ]]; then "$TEMP_DIR/binary" -config "$candidate" -check-config; fi
    TLS_CERT="$requested_cert"; TLS_KEY="$requested_key"
    prepare_tls
    if [[ -f "$CONFIG_FILE" ]]; then
      cp -p "$CONFIG_FILE" "$candidate"
      local bind="$PANEL_HOST" secure=false
      [[ "$bind" != *:* ]] || bind="[$bind]"
      [[ -z "$TLS_CERT" ]] || secure=true
      "$TEMP_DIR/binary" -config "$candidate" -listen "$bind:$PANEL_PORT" -public-host "$PUBLIC_HOST" -external-port 0 -tls-cert "$TLS_CERT" -tls-key "$TLS_KEY" -secure-cookies="$secure" -save-config
    else write_new_config "$candidate"; fi
    if [[ -x "${TEMP_DIR:-}/binary" ]]; then "$TEMP_DIR/binary" -config "$candidate" -check-config; fi
    mv -f "$candidate" "$CONFIG_FILE"
    ACCESS_CANDIDATE=
    CONFIG_CHANGED=1
  else echo 'Существующие параметры доступа сохранены. Для изменения запустите установщик с --configure.'; fi
  # Read existing settings as well: repeat installs must never depend on creation-only variables.
  PANEL_HOST="$(sed -n 's/.*"listenHost":[[:space:]]*"\([^"]*\)".*/\1/p' "$CONFIG_FILE" | head -n 1)"
  PANEL_PORT="$(sed -n 's/.*"listenPort":[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$CONFIG_FILE" | head -n 1)"
  PUBLIC_HOST="$(sed -n 's/.*"publicHost":[[:space:]]*"\([^" ]*\)".*/\1/p' "$CONFIG_FILE" | head -n 1)"
  TLS_CERT="$(sed -n 's/.*"tlsCert":[[:space:]]*"\([^" ]*\)".*/\1/p' "$CONFIG_FILE" | head -n 1)"
  local env_file="$CONFIG_DIR/environment" username password
  if [[ ! -f "$env_file" ]]; then
    username="${FIREWALL_UI_USERNAME:-admin}"; password="${FIREWALL_UI_PASSWORD:-}"
    ask username 'Имя пользователя' "$username"
    [[ -n "$username" && "$username" != *$'\n'* && "$username" != *$'\r'* ]] || { echo 'Неверное имя пользователя.' >&2; return 1; }
    if [[ -z "$password" && "${INSTALL_INTERACTIVE:-0}" == 1 ]]; then
      read -r -s -p 'Пароль (любая длина; Enter — сгенерировать): ' password <&3 || true
      printf '\n' >&3
    fi
    if [[ -z "$password" ]]; then password="$(od -An -N20 -tx1 /dev/urandom | tr -d ' \n')"; echo "Сгенерированный пароль Firewall-UI: $password"; fi
    echo 'Рекомендация: длинный уникальный пароль.'
    [[ -n "$password" && "$password" != *$'\n'* && "$password" != *$'\r'* ]] || { echo 'Перевод строки в пароле не поддерживается.' >&2; return 1; }
    local temp_env; temp_env="$(mktemp "$CONFIG_DIR/.environment-XXXXXX")"
    { printf 'FIREWALL_UI_USERNAME="%s"\n' "$(escape_env_value "$username")"; printf 'FIREWALL_UI_PASSWORD="%s"\n' "$(escape_env_value "$password")"; } > "$temp_env"
    chmod 0600 "$temp_env"; mv -f "$temp_env" "$env_file"
  fi
}

wait_for_service() {
  local i
  for i in {1..20}; do
    if systemctl is-active --quiet firewall-ui.service; then
      sleep 1
      systemctl is-active --quiet firewall-ui.service && return 0
    fi
    sleep .5
  done
  return 1
}

cleanup() {
  local result=$?
  if ((REPLACED && !SUCCEEDED)); then
    systemctl stop firewall-ui.service || true
    if ((!WAS_ENABLED)); then systemctl disable firewall-ui.service || true; fi
    echo 'Установка завершилась ошибкой; восстанавливаем предыдущие файлы службы.' >&2
    if ((HAD_BINARY)); then cp -p "$TEMP_DIR/previous-binary" "$INSTALL_DIR/firewall-ui"; else rm -f "$INSTALL_DIR/firewall-ui"; fi
    local name destination
    for name in manager service installer; do
      if [[ "$name" == manager ]]; then destination="$MANAGER"; elif [[ "$name" == service ]]; then destination="$SERVICE_FILE"; else destination="$INSTALL_DIR/install.sh"; fi
      if [[ -f "$TEMP_DIR/previous-$name" ]]; then cp -p "$TEMP_DIR/previous-$name" "$destination"; else rm -f "$destination"; fi
    done
    systemctl daemon-reload || true
    systemctl reset-failed firewall-ui.service || true
    if ((WAS_ACTIVE)); then systemctl restart firewall-ui.service || true; else systemctl stop firewall-ui.service || true; fi
  fi
  if [[ "${CONFIG_CHANGED:-0}" == 1 && "$SUCCEEDED" == 0 && -f "$TEMP_DIR/previous-config" ]]; then
    cp -p "$TEMP_DIR/previous-config" "$CONFIG_DIR/config.json"
    if ((WAS_ACTIVE)); then systemctl restart firewall-ui.service || true; fi
  fi
  [[ -z "${ACCESS_CANDIDATE:-}" ]] || rm -f -- "$ACCESS_CANDIDATE"
  [[ -z "$TEMP_DIR" ]] || rm -rf -- "$TEMP_DIR"
  rmdir "$INSTALL_DIR" "$CONFIG_DIR" "$STATE_DIR" 2>/dev/null || true
  return "$result"
}

require_installer_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || { echo 'Запустите установщик от root.' >&2; return 1; }
}

installer_directory_has_data() {
  [[ -d "$1" && -n "$(find "$1" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]]
}

installer_detect_installations() {
  NATIVE_INSTALLED=0; COMPOSE_INSTALLED=0
  local docker_dir="${FIREWALL_UI_DOCKER_DIR:-/opt/firewall-ui-docker}"
  if [[ -e "$INSTALL_DIR/firewall-ui" || -e "$SERVICE_FILE" ]] || installer_directory_has_data "$INSTALL_DIR" || installer_directory_has_data "$CONFIG_DIR" || installer_directory_has_data "$STATE_DIR"; then NATIVE_INSTALLED=1; fi
  if installer_directory_has_data "$docker_dir" || [[ -e "${FIREWALL_UI_DOCKER_MANAGER:-/usr/local/bin/firewall-ui-docker}" ]]; then COMPOSE_INSTALLED=1; fi
  if command -v docker >/dev/null 2>&1; then
    if [[ -n "$(docker ps -aq --filter "label=com.docker.compose.project=${FIREWALL_UI_DOCKER_PROJECT:-firewall-ui}" 2>/dev/null)$(docker volume ls -q --filter "label=com.docker.compose.project=${FIREWALL_UI_DOCKER_PROJECT:-firewall-ui}" 2>/dev/null)" ]]; then COMPOSE_INSTALLED=1; fi
  fi
}

installer_require_native_exclusive() {
  command -v docker >/dev/null 2>&1 || return 0
  local running
  running="$(docker ps --filter "label=com.docker.compose.project=${FIREWALL_UI_DOCKER_PROJECT:-firewall-ui}" --filter status=running --format '{{.Names}}' 2>/dev/null)" || {
    if installer_directory_has_data "${FIREWALL_UI_DOCKER_DIR:-/opt/firewall-ui-docker}"; then
      echo 'Не удалось проверить Docker-панель. Проверьте Docker Engine перед обычной установкой.' >&2
      return 1
    fi
    return 0
  }
  [[ -z "$running" ]] || {
    echo 'Остановите Docker-панель перед обычной установкой. Одновременно используйте один вариант управления файрволлом.' >&2
    return 1
  }
}

installer_style() {
  UI_ACCENT=''; UI_MUTED=''; UI_BOLD=''; UI_RESET=''; UI_DANGER=''
  if [[ -t 1 && -z "${NO_COLOR+x}" && "${TERM:-dumb}" != dumb ]]; then
    UI_ACCENT=$'\033[36m'; UI_MUTED=$'\033[2m'; UI_BOLD=$'\033[1m'
    UI_RESET=$'\033[0m'; UI_DANGER=$'\033[31m'
  fi
}

installer_heading() {
  printf '\n%sFirewall-UI%s  /  %s\n' "${UI_BOLD:-}" "${UI_RESET:-}" "$1"
}

installer_item() {
  printf '  %s[%s]%s  %s\n' "${UI_ACCENT:-}" "$1" "${UI_RESET:-}" "$2"
  [[ -z "${3:-}" ]] || printf '       %s%s%s\n' "${UI_MUTED:-}" "$3" "${UI_RESET:-}"
}

installer_pause() {
  local reply
  [[ "${INSTALL_INTERACTIVE:-0}" != 1 ]] || read -r -p 'Нажмите Enter, чтобы вернуться в меню: ' reply <&3
}

installer_settings_menu() {
  local choice
  while true; do
    installer_heading 'Настройки'
    installer_item 1 'Адрес, порт и сертификат' 'Мастер подключения и HTTPS; для Docker — адрес и порт'
    installer_item 2 'Изменить логин и пароль'
    installer_item 3 'Сбросить пароль' 'Текущий логин сохранится'
    installer_item 4 'Показать параметры подключения'
    installer_item 0 'Назад'
    ask choice 'Выберите настройку' 0 || return 1
    case "$choice" in
      1) INSTALL_ACTION=configure;; 2) INSTALL_ACTION=credentials;;
      3) INSTALL_ACTION=reset-password;;
      4) installer_connection_info; installer_pause || return 1; continue;;
      0) INSTALL_ACTION=back; return 0;;
      *) echo 'Введите номер пункта.' >&2; continue;;
    esac
    installer_select_target "$INSTALL_ACTION" || { INSTALL_ACTION=back; return 0; }
    return 0
  done
}

installer_service_menu() {
  local choice
  while true; do
    installer_heading 'Управление службой'
    installer_item 1 'Запустить панель'
    installer_item 2 'Остановить панель' 'Правила файрволла сохраняются'
    installer_item 3 'Перезапустить панель'
    installer_item 4 'Подробное состояние'
    installer_item 0 'Назад'
    ask choice 'Выберите действие' 0 || return 1
    case "$choice" in
      1) INSTALL_ACTION=start;; 2) INSTALL_ACTION=stop;;
      3) INSTALL_ACTION=restart;; 4) INSTALL_ACTION=status;;
      0) INSTALL_ACTION=back; return 0;;
      *) echo 'Введите номер пункта.' >&2; continue;;
    esac
    installer_select_target "$INSTALL_ACTION" || { INSTALL_ACTION=back; return 0; }
    return 0
  done
}

installer_config_value() {
  # Print only named public fields, never environment/password files.
  sed -n "s/.*\"$2\":[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$1" 2>/dev/null | head -n 1
}

installer_connection_info() {
  local config="$CONFIG_DIR/config.json" host port cert scheme=http docker_dir="${FIREWALL_UI_DOCKER_DIR:-/opt/firewall-ui-docker}"
  if [[ -f "$config" ]]; then
    host="$(installer_config_value "$config" publicHost)"
    [[ -n "$host" ]] || host="$(installer_config_value "$config" listenHost)"
    port="$(sed -n 's/.*"listenPort":[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$config" | head -n 1)"
    cert="$(installer_config_value "$config" tlsCert)"; [[ -z "$cert" ]] || scheme=https
    case "$host" in 0.0.0.0|::|'') host='<IP-сервера>';; *:*) host="[$host]";; esac
    printf 'Обычная панель: %s://%s:%s\n' "$scheme" "$host" "$port"
    [[ -z "$cert" ]] || printf 'Сертификат: %s\n' "$cert"
  fi
  if [[ -f "$docker_dir/docker.env" ]]; then
    host="$(sed -n 's/^FIREWALL_UI_DOCKER_HOST=//p' "$docker_dir/docker.env" | head -n 1)"
    port="$(sed -n 's/^FIREWALL_UI_DOCKER_PORT=//p' "$docker_dir/docker.env" | head -n 1)"
    [[ "$host" != 0.0.0.0 ]] || host='<IP-сервера>'
    printf 'Docker: %s:%s (параметры установщика)\n' "$host" "$port"
    echo 'Адрес и HTTPS, изменённые в веб-панели, проверяйте в её настройках.'
  fi
}

installer_diagnostics() {
  installer_heading 'Диагностика'
  printf 'Система: %s / %s\n' "$(uname -s)" "$(uname -m)"
  printf 'Файрволл: %s\n' "$(detect_firewall)"
  installer_status
  installer_connection_info
  if command -v docker >/dev/null 2>&1; then
    docker version --format 'Docker Engine: {{.Server.Version}}' 2>/dev/null || echo 'Docker Engine недоступен.'
    docker compose version 2>/dev/null || echo 'Docker Compose недоступен.'
  fi
  echo 'При проблемах с подключением проверьте порт в файрволле хостинга.'
}

installer_execute_action() {
  local action="$1" answer
  case "$action" in
    exit|back) return 0;;
    install) installer_native_install;;
    configure) FIREWALL_UI_RECONFIGURE=1 installer_native_install;;
    uninstall)
      if [[ "${INSTALL_INTERACTIVE:-0}" == 1 ]]; then
        echo 'Будут удалены оба варианта панели, данные, сертификаты панели и собственные правила, включая запрет пинга.'
        ask answer 'Полностью удалить Firewall-UI? (y/n)' n || return 1
        case "$answer" in y|Y) ;; n|N) echo 'Удаление отменено.'; return 0;; *) echo 'Введите y или n.' >&2; return 1;; esac
      fi
      installer_uninstall_all;;
    diagnostics) installer_diagnostics;;
    docker-logs) run_installer_docker_action logs-once;;
    docker-*) run_installer_docker_action "${action#docker-}";;
    logs) run_installer_manager_action logs-once;;
    reset-password|credentials|start|restart|rollback)
      installer_require_native_exclusive || return 1
      run_installer_manager_action "$action";;
    stop|status) run_installer_manager_action "$action";;
    *) echo 'Неизвестное действие.' >&2; return 1;;
  esac
}

installer_menu_loop() {
  local result
  installer_style
  while true; do
    select_installer_action || return 1
    [[ "$INSTALL_ACTION" != exit ]] || return 0
    # A conditional function call disables Bash errexit throughout nested
    # transactions. Use an unconditional child with its own strict mode.
    set +e
    ( set -Eeuo pipefail; installer_execute_action "$INSTALL_ACTION" )
    result=$?
    set -e
    if ((result)); then printf 'Действие завершилось ошибкой (%s). Причина указана выше.\n' "$result" >&2; fi
    installer_pause || return 0
  done
}

installer_status() {
  installer_detect_installations
  local native='не установлена' compose='не установлен' state version
  if ((NATIVE_INSTALLED)); then
    native='установлена, остановлена'
    if systemctl is-active --quiet firewall-ui.service 2>/dev/null; then native='установлена, запущена'; fi
    [[ -x "$INSTALL_DIR/firewall-ui" ]] || native='остались файлы установки'
  fi
  if ((COMPOSE_INSTALLED)); then
    compose='установлен, остановлен'
    if command -v docker >/dev/null 2>&1; then
      state="$(docker ps --filter "label=com.docker.compose.project=${FIREWALL_UI_DOCKER_PROJECT:-firewall-ui}" --filter status=running --format '{{.Names}}' 2>/dev/null)" || true
      [[ -z "$state" ]] || compose='установлен, запущен'
    fi
  fi
  printf 'Обычная установка: %s\nDocker Compose: %s\n' "$native" "$compose"
  if [[ -x "$INSTALL_DIR/firewall-ui" ]]; then
    version="$("$INSTALL_DIR/firewall-ui" -version 2>/dev/null)" || true
    [[ -z "$version" ]] || printf 'Версия обычной панели: %s\n' "$version"
  fi
}

installer_select_target() {
  local action="$1" choice default=1
  installer_detect_installations
  if [[ "$action" != install ]]; then
    if ((NATIVE_INSTALLED && !COMPOSE_INSTALLED)); then return 0; fi
    if ((COMPOSE_INSTALLED && !NATIVE_INSTALLED)); then INSTALL_ACTION="docker-$action"; return 0; fi
    if ((!NATIVE_INSTALLED && !COMPOSE_INSTALLED)); then echo 'Firewall-UI ещё не установлен.' >&2; return 1; fi
  fi
  if ((!NATIVE_INSTALLED && COMPOSE_INSTALLED)); then default=2; fi
  while true; do
    echo
    echo 'Выберите вариант Firewall-UI:'
    echo '1) Обычная установка'
    echo '2) Docker Compose'
    echo '0) Обратно в главное меню'
    ask choice 'Выберите вариант' "$default" || return 1
    case "$choice" in
      1) INSTALL_ACTION="$action"; return 0;;
      2) INSTALL_ACTION="docker-$action"; return 0;;
      0) INSTALL_ACTION=back; return 0;;
      *) echo 'Введите 1, 2 или 0.' >&2; [[ "${INSTALL_INTERACTIVE:-0}" == 1 ]] || return 1;;
    esac
  done
}

select_installer_action() {
  INSTALL_ACTION=install
  [[ "${INSTALL_INTERACTIVE:-0}" == 1 ]] || { installer_select_target install; return; }
  local choice
  while true; do
    installer_heading 'Установка и обслуживание'
    installer_status
    installer_connection_info
    echo
    installer_item 1 'Установить / обновить' '1 — обычная установка; 2 — Docker Compose; 0 — назад'
    installer_item 2 'Настройки' 'Подключение, логин и пароль'
    installer_item 3 'Сбросить пароль' 'Сохранить текущий логин'
    printf '  %s[4]  Полностью удалить%s\n' "${UI_DANGER:-}" "${UI_RESET:-}"
    printf '       %sОба варианта, данные и собственные правила%s\n' "${UI_MUTED:-}" "${UI_RESET:-}"
    echo
    installer_item 5 'Показать состояние'
    installer_item 6 'Последние записи журнала' '100 строк; меню останется открытым'
    installer_item 7 'Управление службой' 'Запуск, остановка и перезапуск'
    installer_item 8 'Диагностика'
    installer_item 0 'Выход'
    ask choice 'Выберите действие' 0 || return 1
    case "$choice" in
      1) INSTALL_ACTION=install; installer_select_target install || return 1;;
      2) installer_settings_menu || return 1;;
      3) INSTALL_ACTION=reset-password; installer_select_target reset-password || { INSTALL_ACTION=back; };;
      4) INSTALL_ACTION=uninstall; return 0;;
      5) installer_status; installer_pause || return 1; continue;;
      6) INSTALL_ACTION=logs; installer_select_target logs || { INSTALL_ACTION=back; };;
      7) installer_service_menu || return 1;;
      8) INSTALL_ACTION=diagnostics; return 0;;
      0|q|Q) INSTALL_ACTION=exit; return 0;;
      *) echo 'Введите номер пункта.' >&2; continue;;
    esac
    [[ "$INSTALL_ACTION" == back ]] || return 0
  done
}

installer_uninstall_all() {
  installer_detect_installations
  local result=0
  # Empty leftovers are removable without downloading binaries or creating state.
  rmdir "$INSTALL_DIR" "$CONFIG_DIR" "$STATE_DIR" "${FIREWALL_UI_DOCKER_DIR:-/opt/firewall-ui-docker}" 2>/dev/null || true
  installer_detect_installations
  if ((!NATIVE_INSTALLED && !COMPOSE_INSTALLED)); then echo 'Firewall-UI не установлен.'; return 0; fi
  # Try both variants even if one fails; retain failure status and diagnostics.
  if ((COMPOSE_INSTALLED)); then run_installer_docker_action uninstall || result=1; fi
  if ((NATIVE_INSTALLED)); then run_installer_manager_action uninstall --purge || result=1; fi
  if ((result)); then echo 'Удаление завершено не полностью. Исправьте указанные ошибки и повторите пункт 4.' >&2; return 1; fi
  echo 'Все установленные варианты Firewall-UI полностью удалены.'
}

run_installer_manager_action() (
  set -euo pipefail
  local stage
  stage="$(mktemp -d)"
  trap 'rm -rf -- "$stage"' EXIT
  if [[ -x "$MANAGER" ]]; then cp "$MANAGER" "$stage/manager"
  else fetch_repo_file deploy/firewall-ui "$stage/manager"; fi
  if [[ "${INSTALL_INTERACTIVE:-0}" == 1 ]]; then
    bash "$stage/manager" "$@" <&3
  else bash "$stage/manager" "$@"; fi
)

run_installer_docker_action() (
  set -euo pipefail
  local stage
  stage="$(mktemp -d)"; trap 'rm -rf -- "$stage"' EXIT
  local installed="${FIREWALL_UI_DOCKER_MANAGER:-/usr/local/bin/firewall-ui-docker}"
  if [[ "$1" != install && -x "$installed" ]]; then cp "$installed" "$stage/docker-manager"
  else
    command -v curl >/dev/null || pkg_install curl ca-certificates
    fetch_repo_file deploy/firewall-ui-docker "$stage/docker-manager"
  fi
  if [[ -n "$SCRIPT_DIR" && -f "$SCRIPT_DIR/Dockerfile" ]]; then
    export FIREWALL_UI_DOCKER_SOURCE="$SCRIPT_DIR"
  fi
  bash "$stage/docker-manager" "$@"
)

installer_native_install() (
  set -Eeuo pipefail
  check_system
  installer_require_native_exclusive || return 1
  UPDATE_CHANNEL="${FIREWALL_UI_UPDATE_CHANNEL:-}"
  if [[ -z "$UPDATE_CHANNEL" && -f "$CONFIG_DIR/config.json" ]]; then UPDATE_CHANNEL="$(sed -n 's/.*"updateChannel":[[:space:]]*"\([^"]*\)".*/\1/p' "$CONFIG_DIR/config.json" | head -n 1)"; fi
  UPDATE_CHANNEL="${UPDATE_CHANNEL:-stable}"
  [[ "$UPDATE_CHANNEL" == stable || "$UPDATE_CHANNEL" == dev ]] || { echo 'Канал обновления: stable или dev.' >&2; return 1; }
  command -v curl >/dev/null || pkg_install curl ca-certificates
  local backend; backend="$(detect_firewall)"
  if [[ "$backend" == none ]]; then echo 'Поддерживаемый файрволл не найден. Устанавливаем UFW...'; pkg_install ufw; command -v ufw >/dev/null || { echo 'Не удалось установить UFW.' >&2; return 1; }; fi
  echo 'Существующие правила файрволла сохраняются. UFW автоматически не включается.'
  TEMP_DIR="$(mktemp -d)"; trap cleanup EXIT
  download_binary
  fetch_repo_file deploy/firewall-ui "$TEMP_DIR/manager"
  fetch_repo_file deploy/firewall-ui.service "$TEMP_DIR/service"
  fetch_repo_file install.sh "$TEMP_DIR/installer"
  install -d -m 0755 "$INSTALL_DIR"
  install -d -m 0700 "$CONFIG_DIR"
  if [[ -f "$CONFIG_DIR/config.json" ]]; then cp -p "$CONFIG_DIR/config.json" "$TEMP_DIR/previous-config"; fi
  create_settings
  "$TEMP_DIR/binary" -config "$CONFIG_FILE" -check-config
  if [[ -f "$INSTALL_DIR/firewall-ui" ]]; then cp -p "$INSTALL_DIR/firewall-ui" "$TEMP_DIR/previous-binary"; HAD_BINARY=1; fi
  [[ ! -f "$MANAGER" ]] || cp -p "$MANAGER" "$TEMP_DIR/previous-manager"
  [[ ! -f "$SERVICE_FILE" ]] || cp -p "$SERVICE_FILE" "$TEMP_DIR/previous-service"
  [[ ! -f "$INSTALL_DIR/install.sh" ]] || cp -p "$INSTALL_DIR/install.sh" "$TEMP_DIR/previous-installer"
  systemctl is-active --quiet firewall-ui.service && WAS_ACTIVE=1
  systemctl is-enabled --quiet firewall-ui.service && WAS_ENABLED=1
  REPLACED=1
  install -m 0755 "$TEMP_DIR/binary" "$INSTALL_DIR/firewall-ui.new"; mv -f "$INSTALL_DIR/firewall-ui.new" "$INSTALL_DIR/firewall-ui"
  install -m 0755 "$TEMP_DIR/manager" "$MANAGER"
  install -m 0644 "$TEMP_DIR/service" "$SERVICE_FILE"
  install -m 0700 "$TEMP_DIR/installer" "$INSTALL_DIR/install.sh"
  systemctl daemon-reload
  systemctl enable firewall-ui.service
  systemctl reset-failed firewall-ui.service || true
  systemctl restart firewall-ui.service
  if ! wait_for_service; then systemctl status --no-pager firewall-ui.service || true; return 1; fi
  if ((HAD_BINARY)); then cp -p "$TEMP_DIR/previous-binary" "$INSTALL_DIR/firewall-ui.previous"; fi
  allow_access_port "$PANEL_PORT"
  setup_renewal
  SUCCEEDED=1
  echo 'Firewall-UI установлен.'
  show_panel_url
  echo 'Управление: firewall-ui; журнал: firewall-ui logs'

)

main() {
  INSTALL_ACTION=install
  case "${1:-}" in
    --menu) ;;
    --help|-h) echo 'Использование: install.sh [--menu|--check|--configure|--reset-password|--uninstall|--compose|--compose-configure|--compose-reset-password|--compose-uninstall]. Без параметров — русское меню. FIREWALL_UI_NONINTERACTIVE=1 — без вопросов.'; return;;
    --check) check_system; return;;
    --configure) INSTALL_ACTION=configure;;
    --reset-password) INSTALL_ACTION=reset-password;;
    --uninstall) INSTALL_ACTION=uninstall;;
    --compose|--docker) INSTALL_ACTION=docker-install;;
    --compose-configure|--docker-configure) INSTALL_ACTION=docker-configure;;
    --compose-reset-password|--docker-reset-password) INSTALL_ACTION=docker-reset-password;;
    --compose-uninstall|--docker-uninstall) INSTALL_ACTION=docker-uninstall;;
    '') ;;
    *) echo 'Неизвестный параметр.' >&2; return 1;;
  esac
  require_installer_root || return 1
  INSTALL_INTERACTIVE=0
  if [[ "${FIREWALL_UI_NONINTERACTIVE:-0}" != 1 ]] && { exec 3<>/dev/tty; } 2>/dev/null; then INSTALL_INTERACTIVE=1; fi
  if [[ -z "${1:-}" || "${1:-}" == --menu ]]; then
    if [[ "$INSTALL_INTERACTIVE" == 1 ]]; then installer_menu_loop; return; fi
    [[ "${1:-}" != --menu ]] || { echo 'Для меню нужен интерактивный терминал.' >&2; return 1; }
    installer_select_target install || return 1
  elif [[ "$INSTALL_ACTION" == configure || "$INSTALL_ACTION" == reset-password ]]; then
    installer_select_target "$INSTALL_ACTION" || return 1
    [[ "$INSTALL_ACTION" != back ]] || return 0
  fi
  installer_execute_action "$INSTALL_ACTION"

}
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
