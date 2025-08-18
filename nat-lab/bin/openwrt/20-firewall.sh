#!/bin/sh
set -ex
uci add firewall rule
uci set firewall.@rule[-1].name="Allow-Admin"
uci set firewall.@rule[-1].enabled="true"
uci set firewall.@rule[-1].src="wan"
uci set firewall.@rule[-1].proto="tcp"
uci set firewall.@rule[-1].dest_port="22 80 443"
uci set firewall.@rule[-1].target="ACCEPT"
uci commit firewall
