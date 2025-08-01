#!/bin/sh
set -e

echo "==== Mount table at container startup ===="
mount

echo
echo "==== Checking for tmpfs/overlay mounts on /bin, /etc, /usr, /root ===="
mount | grep -E "/bin|/etc|/usr|/root"

echo
echo "==== Contents of /bin before OpenWrt init ===="
ls -L /bin | head -20

echo "==== Opkg type ===="
find / -type f -name 'opkg'

mkdir -p /var/lock

echo
echo "==== Running opkg update/install ===="
opkg update
opkg install kmod-wireguard
opkg install kmod-tun

echo
echo "==== Mount table after opkg operations ===="
mount

echo
echo "==== Checking /bin, /etc, /usr, /root overlays again ===="
mount | grep -E "/bin|/etc|/usr|/root"

echo
echo "Files in /opt/bin:"
ls -l /opt/bin/

echo
echo "/bin/opkg:"
ls -l /bin/opkg || echo "/bin/opkg not found"

echo
echo "OPKG list:"
opkg list || echo "opkg not working"

echo
echo "[OpenWRT Gateway] Startup complete. Entering sleep."
exec sleep infinity
