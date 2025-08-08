FROM openwrt/rootfs:x86-64-v24.10.2

RUN mkdir -p /var/lock && opkg update && opkg install kmod-wireguard kmod-tun curl ca-bundle ca-certificates conntrack iptables ip6tables tcpdump

COPY --chmod=0755 bin/ /opt/bin/
