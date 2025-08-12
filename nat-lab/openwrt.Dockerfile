FROM openwrt/rootfs:x86-64-v24.10.2

RUN mkdir -p /var/lock && opkg update && opkg install curl ca-bundle ca-certificates

COPY --chmod=0755 bin/ /opt/bin/

RUN opkg install /opt/bin/nordvpn_*_x86_64.ipk
