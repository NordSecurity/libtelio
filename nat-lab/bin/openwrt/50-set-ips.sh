#!/bin/sh
set -ex
# Assign IP 192.168.115.254/24 to LAN bridge (br-lan)
uci set network.lan.ifname='br-lan'
uci set network.lan.proto='static'
uci set network.lan.ipaddr='192.168.115.254'
uci set network.lan.netmask='255.255.255.0'

# Assign IP 10.0.0.1/31 to WAN interface (eth1)
uci set network.wan.ifname='eth1'
uci set network.wan.proto='static'
uci set network.wan.ipaddr='10.0.0.0'
uci set network.wan.netmask='255.255.255.254'

# Add defailt gateway via 10.0.0.1
uci set network.wan.gateway='10.0.0.1'

uci commit network
/etc/init.d/network restart
