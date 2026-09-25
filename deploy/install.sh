#!/bin/sh
# Instalacja formd na Linuksie z systemd. Uruchom jako root.
set -eu
BIN=${1:-./formd}

id formd >/dev/null 2>&1 || useradd --system --home /var/lib/formd --shell /usr/sbin/nologin formd
install -m 0755 "$BIN" /usr/local/bin/formd
install -d -m 0750 -o root -g formd /etc/formd
if [ ! -f /etc/formd/formd.env ]; then
    install -m 0640 -o root -g formd .env.example /etc/formd/formd.env
    sed -i 's#^DB_PATH=.*#DB_PATH=/var/lib/formd/formd.db#' /etc/formd/formd.env
    echo "Uzupełnij /etc/formd/formd.env"
fi
install -m 0644 deploy/formd.service /etc/systemd/system/formd.service
systemctl daemon-reload
echo "Następnie:"
echo "  systemctl enable --now formd"
echo "  sudo -u formd formd -env /etc/formd/formd.env user add admin"
