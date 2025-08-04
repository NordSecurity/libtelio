#!/bin/sh
set -e


echo "Files in docker container:"
ls -l /opt/bin

echo "IPK file debug info:"
ls -lah /opt/bin/*.ipk
md5sum /opt/bin/*.ipk
sha256sum /opt/bin/*.ipk
head -c 256 /opt/bin/*.ipk | hexdump -C

opkg --version
uname -a

opkg install /opt/bin/nordvpn_ee3967fc8f672aecf9ac6c3686964a62b0b70442-r1_x86_64.ipk -V4

exec sleep infinity
