# Changelog

## 1.3.0

- Enlarge the shield favicon, fill it with visible masonry and keep the outside transparent.
- Consolidate Docker assets under deploy/docker and documentation under docs; keep build output in dist.
- Remove uncalled backend helpers and clarify current UFW/firewalld adapters.
- Limit Docker build context to production sources.
- Match overview rules against observed ports using merged intervals instead of expanding ranges; include full ranges and ANY protocol rules.
- Skip process-descriptor scans when all socket inodes are ownerless.

## 1.2.26

- Add a shield and firewall favicon.
- Smooth cyberpunk backgrounds and remove opaque sidebar menu/collapse surfaces.
- Use fw-ui as the native/Compose management command; migrate owned legacy helpers and certificate renewal hooks.

## 1.2.25

- Suggest public IP or a matching server domain in the shared native/Compose HTTPS wizard; retain saved addresses.
- Restore TCP + UDP port summaries and show matching TCP / UDP firewall rules in expandable rows with individual actions.
- Move journal and diagnostics into service management and shorten Compose installation documentation.

## 1.2.24

- Scope session cookies by panel port and transport; verify the browser returned the session before mounting protected pages and explain blocked cookies.
- Reuse the native Russian domain/IP/HTTPS wizard in Compose, including PEM import, self-signed certificates, ACME renewal and owned host access-rule cleanup.
- Refine cyberpunk button variants, card corners and table backgrounds to avoid unwanted surfaces and seams.
- Verify browser login and mobile/desktop rendering, plus Docker HTTPS-to-HTTP reconfiguration on amd64/arm64.

## 1.2.23

- Exclude unrelated Compose services and volumes from installation/running status and native-install conflict checks.
- Verify that retaining an unrelated project volume after complete removal does not leave the panel marked as installed.

## 1.2.22

- Remove repeated status, connection and password-reset menu entries; keep state and connection details in the main header.
- Display combined TCP/UDP groups and protocol choices as `tcp/udp` in desktop/mobile ports and overview.
- Use current removal helpers with offline fallback and verify native files are removed before reporting success.
- Reuse capable installed cleanup images for offline Compose removal, preserve unrelated services/volumes and verify owned resources are gone before reporting success.
- Test offline removal, old-image fallback and unrelated-volume preservation on both Docker architectures.

## 1.2.21

- Redirect accidental plaintext GET/HEAD requests on the HTTPS port to the configured domain/IP, preserving paths and queries without trusting client Host headers.
- Reject plaintext credential submissions and malformed TLS; retain certificate and server failure diagnostics.
- Silence routine EOF disconnects during TLS negotiation while keeping per-connection deadlines and concurrent HTTPS handling.

## 1.2.20

- Replace separate server menus with one persistent Russian menu, terminal-only colors, contextual status, connection details, settings, service controls and diagnostics.
- Retain numeric native/Compose selection and y/n confirmations; confirm full removal with cancellation as the default.
- Save the standalone menu locally, return after actions/errors and show bounded logs without blocking navigation.
- Add Compose credential changes and service controls; preserve current usernames on blank input and write native credentials atomically.
- Default access settings to the saved mode and allow certificate type changes during reconfiguration.

## 1.2.19

- Prevent native installation while the Compose panel is running.
- Stop partial Docker deployments and restore runtime configuration, metadata and image after failed updates; allow failed first installations to be retried correctly.
- Clear retained TLS settings when explicitly selecting Docker HTTP access.
- Apply ping preferences only while panel firewall management is enabled; restore echo replies immediately when disabling it.
- Verify Docker rollback with an occupied port on both supported architectures.

## 1.2.18

- Restore owned IPv4/IPv6 ping bans during removal; tolerate missing systemd units and recover cleanup when installed binaries or Compose metadata are missing.
- Build and test amd64/arm64 container images on GitHub and publish verified ready-to-load images with releases. Install/update without server-side builds or Buildx.
- Avoid recreating state during cleanup, omit unused data directories and reject missing bind paths instead of creating empty host folders.

## 1.2.17

- Select installation type with 1 (native), 2 (Docker Compose), or 0 (back to the main menu).

## 1.2.16

- Unify installer actions, display installed/running variants, ask for Docker Compose on installation/update, and purge both variants with one action. Route settings and password reset to the installed variant automatically.

## 1.2.15

- Remove Docker network proxy deployment, its installer options and namespace switching; use direct host networking with local or IP access.
- Remove panel integration, metadata polling, API routes, settings and inbound labels. Clear retired credentials from existing configuration files during upgrade.

## 1.2.9

- Make cyberpunk the default theme and the first option in the theme selector; preserve saved light/dark/cyberpunk preferences.

## 1.2.7

- Split nonconsecutive ports into separate rows and ranges in active ports, firewall rules, overview and container publications. Never include missing ports in a range.
- Label wildcard and loopback bind addresses clearly; retain copyable exact IPv4/IPv6 endpoints.
- Add expandable application ranges to overview and exposed-port lists.
- Run frontend and backend checks in parallel, cache Go compilation by architecture and build Linux architectures in parallel. Publish checked artifacts without repeating tests or frontend compilation.

## 1.2.6

- Restore neon gradients, ambient background, luminous buttons and subtle shimmer exclusively in cyberpunk; retain the light and dark styles. Respect reduced motion.
- Group workers of the same executable into one expandable hyphenated port range while preserving exact socket owners and individual controls.
- Add expandable ranges to active firewall rules; keep protected/manual rules, protocols and access states separate and label gaps explicitly.

## 1.2.5

- Retain only light, dark and cyberpunk themes; replace inherited page/sidebar styles and continuous visual effects with three static palettes using local system fonts.
- Remove unused theme APIs, obsolete firewall mutation APIs and their unused trigger/bulk replacement paths; remove the retired 2FA compatibility test.
- Pause overview polling and port streams in hidden tabs; avoid overlapping overview requests and paginate exposed-port lists.
- Handle failed GET requests without unhandled promise rejections or permanently pending page loaders.
- Memoize port search indexes and filtering; stream only changes to owned active sockets in the default view.
- Avoid reading process metadata for unrelated sockets and cache Docker/Podman inspection for 30 seconds.

## 1.2.4

- Show a process-wide min-max port extent with an ASCII hyphen, exact port count and explicit gap indication; retain precise per-protocol ranges in expanded details.
- Rework active ports into a responsive toolbar and readable expandable process table with aligned access controls.
- Fix page containment and compact button sizing to avoid viewport overflow and clipped table actions.

## 1.2.3

- Use English y/n responses in terminal confirmation prompts while retaining Russian descriptions.
- Validate installer confirmation input instead of silently interpreting invalid answers.

## 1.2.2

- Group port rows by process/PID with expandable details and consecutive ranges written with hyphens; preserve gaps and individual firewall controls.
- Remove TOTP/2FA from login, settings, APIs and configuration; legacy configurations no longer require a second factor.
- Add a Russian installer menu with password reset and full removal, available before installation dependencies are checked.
- Reset passwords atomically while preserving the existing username and environment settings.

## 1.2.1

- Add username/password changes in web settings, current-password/2FA verification, atomic persistence and session revocation.
- Group listening sockets by endpoint; move temporary and ownerless sockets to optional diagnostics.
- Stop automatically opening sockets without a process owner.
- Add explicit close/reopen actions in port and firewall tables, with priority over auto-open rules and panel/SSH protection.

- Add `firewall-ui uninstall --purge` and a Russian full-removal menu option.
- Remove owned firewall rules, including inactive UFW policy, without disabling the system firewall.
- Track installer-created firewalld access rules separately from existing administrator ports.
- Stop the panel and certificate renewal before removal; preserve files on cleanup failure.
- Purge installation, credentials, state, local certificates and renewal units.

## 1.2.0

- Accept simple nonempty passwords; replace minimum-length enforcement with recommendations.
- Add a Russian installation wizard for local access or external domain/IP HTTPS access.
- Choose existing PEM files, Let's Encrypt certificates or self-signed certificates with DNS/IP SANs.
- Add isolated Certbot renewal with a twice-daily systemd timer and panel restart after renewal.
- Support Let’s Encrypt IP certificates when Certbot has IP/profile support.
- Add `--configure` to change installation access while preserving credentials, 2FA and other settings.
- Store the public connection host separately from the bind interface and show its URL in web settings.
- Validate certificate coverage for the selected domain/IP and retain TLS form values when saving.

## 1.1.4

- Serialize runtime settings, TOTP setup/confirmation/disable and backup configuration writes.
- Preserve current two-factor authentication settings when runtime backups roll back.
- Avoid overwriting newer runtime edits during an expired backup transaction.
- Report runtime rollback save failures in the audit result and keep memory unchanged on failed writes.
- Reject trailing JSON/data in backup imports.
- Remove a redundant post-commit chmod that could report a failed save after the file was replaced.

## 1.1.3

- Validate configuration before CLI updates/rollback and atomically replace executables.
- Verify sustained service activity after restart and restore the current version if startup fails.
- Preserve previous versions on failed updates; swap versions on a successful rollback.
- Restrict self-update assets to this repository's releases and the current CPU architecture.
- Fix live port subscription shutdown races and deliver the latest snapshot to slow clients.
- Count all listening/public ports even when the risk preview reaches its 30-row limit.
- Detect TLS, external-port and cookie changes when restoring runtime backups.
- Run installer and CLI regression checks before publishing releases.

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

- Standalone Linux firewall web panel.
- UFW, firewalld, nftables and iptables support with safe managed rules.
- Automatic host TCP/UDP port and owning-process discovery.
- Manual rules, ping control, SSH/panel lockout protection and auto-sync.
- Responsive React/Ant Design UI with Russian/English and six themes.
- Server installer, systemd service and management CLI.
- Persistent web-panel settings.
- Stable/manual and rolling Dev/automatic update channels.
- Checksum-verified atomic self-updates.
- Automated amd64/arm64 Stable and Dev release publishing.
