#!/bin/sh
set -e

echo "==== OS release ===="
cat /etc/os-release

opkg

exec sleep infinity
