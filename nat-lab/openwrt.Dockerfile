FROM openwrt/rootfs:x86-64-openwrt-24.10
RUN mkdir -p /var/lock && opkg update && opkg install kmod-wireguard && opkg install kmod-tun
