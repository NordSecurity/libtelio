#!/bin/sh
set -e

opkg --version
uname -a

opkg install /opt/bin/nordvpn_*_x86_64.ipk

exec sleep infinity
