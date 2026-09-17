#!/bin/sh

# Backup IP tables
iptables-save -f iptables_backup
ip6tables-save -f ip6tables_backup

/opt/bin/tp-lite-dns-server 2>&1 | tee /tp-lite-dns-server.log
