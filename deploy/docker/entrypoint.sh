#!/bin/sh
set -eu
umask 077
mkdir -p /etc/firewall-ui /var/lib/firewall-ui
chmod 700 /etc/firewall-ui /var/lib/firewall-ui
# Only initialize once: later changes to the port/TLS settings remain effective.
if [ ! -f /etc/firewall-ui/config.json ]; then
    /usr/local/bin/firewall-ui -save-config
fi
exec /usr/local/bin/firewall-ui "$@"
