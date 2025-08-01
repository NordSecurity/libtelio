#!/bin/sh
set -e

echo "==== OS release ===="
cat /etc/os-release

opkg install /opt/bin/nordvpn_*-r1_x86_64.ipk

exec sleep infinity
