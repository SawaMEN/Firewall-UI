# Changelog

## 1.1.2

- Remove the retained mobile drawer backdrop after closing navigation.

## 1.1.1

- Fix redirect loops when serving the web panel root and SPA pages.
- Keep empty socket/process/container arrays serializable so the live ports page cannot crash.
- Make mobile tables scroll without a pinned action column and keep the menu accessible.
- Verify release binaries during first installation and preserve configuration on repeated installs.
- Restart existing services after installation and roll back binaries/CLI/unit on failure.
- Detect active firewall backends and install UFW only when none is installed.
- Add editable PEM certificate/key settings and validate TLS before saving.
- Add noninteractive installer setup, read-only system checks and CLI configuration validation.
- Load interface sections on demand and remove circular JavaScript chunk dependencies.


## 1.1.0

Security, policy and operations release.

- Confirmed firewall transactions with automatic rollback when the UI cannot confirm connectivity.
- Advanced allow/deny policies with CIDR/IP sources, TCP/UDP port ranges, IPv4/IPv6 selection, interfaces and priority.
- TOTP two-factor authentication and panel IP/CIDR allowlists.
- Stricter login rate limiting with Retry-After responses.
- Safer installer defaults: localhost-only panel binding unless explicitly exposed.
- Dashboard for firewall health, public listeners, potentially exposed ports and containers.
- Cached host socket monitoring with SSE live updates instead of per-request /proc scans.
- Docker and Podman published-port discovery with container/image mapping.
- Inline allow/remove firewall actions directly from the ports/processes view.
- Persistent JSONL audit log and restorable firewall history snapshots.
- Full firewall/runtime backup export and restore.
- UFW deletion by Firewall-UI ownership comments instead of ambiguous rule specs.
- SHA-256 verified CLI updates, retained previous binary and `firewall-ui rollback`.
- Production dependency audit in CI and split frontend vendor bundles.
- Regression tests for TOTP/CIDR, rollback, container port parsing, UFW ownership and advanced policies.

## 1.0.0

First stable standalone Firewall-UI release.

- Standalone Linux firewall web panel extracted from 3x-ui.
- UFW, firewalld, nftables and iptables support with safe managed rules.
- Automatic host TCP/UDP port and owning-process discovery.
- Manual rules, ping control, SSH/panel lockout protection and auto-sync.
- Responsive React/Ant Design UI with Russian/English and six themes.
- Server installer, systemd service and management CLI.
- Persistent web-panel settings.
- Stable/manual and rolling Dev/automatic update channels.
- Checksum-verified atomic self-updates.
- Automated amd64/arm64 Stable and Dev release publishing.
