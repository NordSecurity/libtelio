#!/bin/sh
set -e


echo "Files in docker container:"
RUN ls -l /opt/bin

echo "IPK file debug info:"
ls -lah /opt/bin/*.ipk
md5sum /opt/bin/*.ipk
ar t /opt/bin/*.ipk || echo "ar extraction failed"
head -c 256 /opt/bin/*.ipk | hexdump -C

opkg --version
uname -a

exec sleep infinity
