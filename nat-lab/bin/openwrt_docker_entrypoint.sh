#!/bin/sh
set -e
mkdir -p /var/lock
opkg update
opkg install kmod-wireguard
install kmod-tun
echo "Files:"
echo "Opt bin files:"
ls -l /opt/bin/
echo "Bin/opkg"
ls -l /bin/opkg
echo "OPKG list:"
opkg list
echo "[OpenWRT Gateway] Startup complete. Entering sleep."
exec sleep infinity
