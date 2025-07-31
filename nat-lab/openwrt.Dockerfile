FROM openwrt/rootfs:x86-64-openwrt-24.10
RUN mkdir -p /var/lock && opkg update && opkg install kmod-wireguard && opkg install kmod-tun
COPY --chmod=0755 bin/ /opt/bin/
RUN opkg --version
RUN opkg install nordvpn_*-r1_x86_64.ipk
