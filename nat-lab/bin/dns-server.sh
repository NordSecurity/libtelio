#!/bin/sh

# Backup IP tables
iptables-save -f iptables_backup
ip6tables-save -f ip6tables_backup

/opt/bin/dns-server 2>&1 | tee /dns-server.log
