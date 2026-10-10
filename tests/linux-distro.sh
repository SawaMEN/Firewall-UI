#!/usr/bin/env bash
# Runs only inside disposable, privileged CI containers with their own network.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

prepare() {
  source "$ROOT/install.sh"
  source /etc/os-release
  case "$ID" in
    arch)
      # Synchronize the disposable rolling image without a partial upgrade.
      pacman -Syu --noconfirm
      pkg_install curl ca-certificates openssl python systemd ufw
      ;;
    debian|ubuntu) pkg_install curl ca-certificates openssl python3 systemd systemd-sysv ufw;;
    fedora) pkg_install curl-minimal ca-certificates openssl python3 systemd ufw;;
    opensuse-leap|opensuse-tumbleweed) pkg_install curl ca-certificates openssl python3 systemd firewalld;;
    *) echo "Unknown CI distribution: $ID" >&2; return 1;;
  esac
  # A container has no physical consoles or disks to configure.
  systemctl mask systemd-remount-fs.service systemd-udevd.service console-getty.service getty.target
}

verify() {
  local expected=ufw
  source /etc/os-release
  if [[ "$ID" == opensuse-* ]]; then
    expected=firewalld
    systemctl start firewalld
  fi
  export FIREWALL_UI_NONINTERACTIVE=1 FIREWALL_UI_USERNAME=admin FIREWALL_UI_PASSWORD=1
  export FIREWALL_UI_BINARY=/opt/testbin/firewall-ui
  export FIREWALL_UI_SHA256
  FIREWALL_UI_SHA256="$(sha256sum "$FIREWALL_UI_BINARY" | awk '{print $1}')"
  export FIREWALL_UI_PORT=18089 FIREWALL_UI_ACCESS_MODE=local
  bash "$ROOT/install.sh"
  systemctl is-active --quiet firewall-ui.service
  /usr/local/firewall-ui/firewall-ui -config /etc/firewall-ui/config.json -check-config
  python3 -m http.server 18889 --bind 127.0.0.1 >/tmp/listener.log 2>&1 &
  DISTRO_LISTENER_PID=$!
  trap 'kill "$DISTRO_LISTENER_PID" 2>/dev/null || true' EXIT
  FIREWALL_UI_TEST_BACKEND="$expected" python3 "$ROOT/tests/linux-distro.py" mutate
  # Repeat install must preserve existing configuration, credentials and rules.
  bash "$ROOT/install.sh"
  FIREWALL_UI_TEST_BACKEND="$expected" python3 "$ROOT/tests/linux-distro.py" preserved
  FIREWALL_UI_PASSWORD=changed bash "$ROOT/install.sh" --reset-password
  FIREWALL_UI_PASSWORD=changed FIREWALL_UI_TEST_BACKEND="$expected" python3 "$ROOT/tests/linux-distro.py" preserved
  /usr/local/bin/fw-ui uninstall --purge
  [[ ! -e /usr/local/firewall-ui && ! -e /etc/firewall-ui && ! -e /var/lib/firewall-ui && ! -e /usr/local/bin/fw-ui ]]
  ! systemctl is-active --quiet firewall-ui.service
  [[ "$(cat /proc/sys/net/ipv4/icmp_echo_ignore_all)" == 0 ]]
  if [[ "$expected" == ufw ]]; then
    local rules
    rules="$(LC_ALL=C ufw show added)"
    [[ "$rules" == *20092* && "$rules" != *20091* && "$rules" != *20093* ]]
  else
    firewall-cmd --query-port=20092/tcp
    ! firewall-cmd --query-port=20091/tcp
    ! firewall-cmd --query-port=20093/tcp
  fi
  echo "$PRETTY_NAME: install, login, process monitoring, rules, ping, repeat install, password reset and purge passed"
}

case "${1:-}" in prepare) prepare;; verify) verify;; *) exit 2;; esac
