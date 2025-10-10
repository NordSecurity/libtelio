#!/bin/sh
set -ex
uci set dhcp.@dnsmasq[0].noresolv="1"
uci add_list dhcp.@dnsmasq[0].server="10.0.80.82"
uci add_list dhcp.@dnsmasq[0].rebind_domain="api.nordvpn.com"
uci commit dhcp
/etc/init.d/dnsmasq restart
