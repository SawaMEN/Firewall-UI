# Source attribution

Firewall-UI derives its firewall service, backend detection and installation, firewall manager/page, theme provider, sidebar CSS and shared theme CSS from SawaMEN/3x-ui (GPL-3.0).

Source: https://github.com/SawaMEN/3x-ui
Source commit: cf730af652387a2e99fa1cda20674b038a6edfdf
Original source paths: internal/web/service/firewall*.go, internal/firewall/*.go, frontend/src/pages/firewall/*, frontend/src/hooks/useTheme.tsx, frontend/src/layouts/AppSidebar.css, frontend/src/styles/material-ui.css, frontend/src/styles/page-shell.css.

Modifications replace the panel database and inbound dependencies with atomic file settings and host socket discovery, add an independent authenticated HTTP server and process table, and provide standalone navigation, deployment and build support. Copyright notices and the original GPL license are retained.
