#!/bin/sh
set -e
echo "Files:"
ls -l
echo "Opt bin files:"
ls -l /opt/bin/
find / -type f -name 'opkg'
echo "OPKG list:"
opkg list
echo "[OpenWRT Gateway] Startup complete. Entering sleep."
exec sleep infinity
