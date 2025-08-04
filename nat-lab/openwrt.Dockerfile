FROM openwrt/rootfs:x86-64-v24.10.2
RUN mkdir -p /var/lock && opkg update && opkg install kmod-wireguard && opkg install kmod-tun
COPY --chmod=0755 bin/ /opt/bin/
RUN opkg --version
RUN ls -l /opt/bin
RUN find / -type f -name 'opkg'
