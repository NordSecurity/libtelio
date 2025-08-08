#!/bin/sh
set -e

opkg --version
uname -a

opkg install /opt/bin/nordvpn_*_x86_64.ipk

# Backup IP tables
iptables-save -f iptables_backup
ip6tables-save -f ip6tables_backup

exec sleep infinity
