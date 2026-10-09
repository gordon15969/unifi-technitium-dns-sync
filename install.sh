#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this installer as root." >&2
  exit 1
fi

command -v python3 >/dev/null 2>&1 || {
  echo "Python 3 is required. On Debian/Ubuntu: apt install python3" >&2
  exit 1
}

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

getent group unifi-dns-sync >/dev/null 2>&1 ||
  groupadd --system unifi-dns-sync
id unifi-dns-sync >/dev/null 2>&1 ||
  useradd --system --gid unifi-dns-sync --home-dir /var/lib/unifi-technitium-sync \
    --shell /usr/sbin/nologin unifi-dns-sync

# systemd runs the program from /opt, so the program directory and the
# directories above it must be owned by root and writable by nobody else;
# otherwise another local user could swap the code before it next starts.
APP_DIR=/opt/unifi-technitium-sync
for dir in / /opt; do
  if [ -L "$dir" ] || [ "$(stat -c %u "$dir")" != 0 ] || [ -n "$(find "$dir" -maxdepth 0 -perm /022)" ]; then
    echo "$dir must be a root-owned directory that only root can write; refusing to install." >&2
    exit 1
  fi
done
if [ -L "$APP_DIR" ] || { [ -e "$APP_DIR" ] && [ ! -d "$APP_DIR" ]; }; then
  echo "$APP_DIR exists but is not a plain directory; refusing to install into it." >&2
  exit 1
fi
install -d -m 0755 -o root -g root "$APP_DIR"
chown root:root "$APP_DIR"   # install -d leaves an existing directory's owner alone
chmod 0755 "$APP_DIR"
rm -rf -- "$APP_DIR/__pycache__"
install -m 0755 "$SCRIPT_DIR/unifi_technitium_sync.py" \
  /opt/unifi-technitium-sync/unifi_technitium_sync.py
install -m 0644 "$SCRIPT_DIR/unifi_technitium_web.py" \
  /opt/unifi-technitium-sync/unifi_technitium_web.py

# The service user may write the settings file so the web UI can save changes;
# the directory and file stay unreadable to everyone else.
install -d -m 0770 -o root -g unifi-dns-sync /etc/unifi-technitium-sync
if [ ! -e /etc/unifi-technitium-sync/sync.env ]; then
  install -m 0660 -o root -g unifi-dns-sync \
    "$SCRIPT_DIR/unifi-technitium-sync.env.example" \
    /etc/unifi-technitium-sync/sync.env
else
  chgrp unifi-dns-sync /etc/unifi-technitium-sync/sync.env
  chmod 0660 /etc/unifi-technitium-sync/sync.env
fi

install -d -m 0750 -o unifi-dns-sync -g unifi-dns-sync \
  /var/lib/unifi-technitium-sync
install -m 0644 "$SCRIPT_DIR/unifi-technitium-sync.service" \
  /etc/systemd/system/unifi-technitium-sync.service

systemctl daemon-reload

echo "Installed."
echo "1. Edit /etc/unifi-technitium-sync/sync.env"
echo "2. Test with the dry-run command shown in README.md"
echo "3. Enable the service after reviewing the dry-run output"
echo "4. Optional web UI: set a password with"
echo "     /opt/unifi-technitium-sync/unifi_technitium_sync.py --config /etc/unifi-technitium-sync/sync.env --set-web-password"
echo "   then set WEB_LISTEN in sync.env and restart the service: 127.0.0.1:8089 for an"
echo "   SSH tunnel or reverse proxy, or a LAN address together with WEB_TLS_CERT and"
echo "   WEB_TLS_KEY (plain HTTP on the LAN is refused; see README \"Web UI\")"
