#!/bin/sh
set -e
echo "Files:"
echo "Opt bin files:"
ls -l /opt/bin/
echo "Bin/opkg"
ls -l /bin/opkg
echo "OPKG list:"
opkg list
echo "[OpenWRT Gateway] Startup complete. Entering sleep."
exec sleep infinity
