# Firewall-UI 1.4.0 review

Reviewed the 47 commits dated 22 October 2026 (UTC), together with the complete
resulting diff since v1.3.7. Two older post-1.3.7 commits are retained in the
consolidated snapshot so Docker protection, diagnostics and CI changes are not lost.
The release has one parent, the unchanged v1.3.7 commit.

## Corrections made during this review

- Backups now export, validate and restore the synchronization interval; omitted fields in older backups preserve the current setting.
- Restoring a different firewalld zone checks the live daemon state before removing rules or writing settings; a stale disabled preference cannot bypass the guard.
- Rich-rule deletion no longer treats source-port or forward-port text as a destination port. Ambiguous logging expressions remain read-only.
- UFW external-rule parsing distinguishes source/destination ports. Outgoing and source-port-restricted rules cannot satisfy unrestricted inbound ALLOW coverage.
- UFW advanced reconciliation shares numbered/saved snapshots across closed ports, refreshes them after changes and removes unreachable duplicate logic.
- Intermediate release notes are consolidated under 1.4.0. CI retires 1.3.8–1.3.18 tags/releases only after publishing and verifying 1.4.0 assets.

## Validation

Go tests with race detection, Go vet, frontend unit tests, TypeScript and production
build, shell/installer/update/manifest regressions, plus the browser regression suite.
Host firewall unit tests use temporary executable fixtures and sysctl files.
Live distribution/container CI checks remain the final release gates. No tests
establish connectivity on an unseen production server or through its upstream firewall.
