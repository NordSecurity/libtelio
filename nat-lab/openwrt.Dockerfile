ARG SEC_CONTAINER_REGISTRY

FROM ${SEC_CONTAINER_REGISTRY}/nord-projects/nordvpn/infra/llt/third-party-build/openwrt_image/natlab-openwrt-24.10.4-x86-64:v0.4.0

ENV QEMU_CONFIG_TIMEOUT="300"

COPY --chmod=0755 bin/ /opt/bin/

WORKDIR /ipk-source
COPY data/core_api/test.pem /ipk-source/

RUN mkdir -p /var/lib/qemu-image
WORKDIR /var/lib/qemu-image

RUN mkdir -p /var/lib/qemu && \
    gunzip -c openwrt-24.10.4-x86-64-generic-ext4-combined.img.gz > /var/lib/qemu/image.raw

RUN mkdir -p /usr/local/share/vmconfig/container.d /usr/local/share/vmconfig/vm.d
RUN mkdir -p /var/lib/vmconfig/container.d /var/lib/vmconfig/vm.d

RUN ln -s /opt/bin/openwrt/10-usbmount-initsh.sh    /usr/local/share/vmconfig/vm.d/10-usbmount-initsh.sh && \
    ln -s /opt/bin/openwrt/20-firewall.sh           /usr/local/share/vmconfig/vm.d/20-firewall.sh && \
    ln -s /opt/bin/openwrt/30-wait-for-network.sh   /usr/local/share/vmconfig/vm.d/30-wait-for-network.sh && \
    ln -s /opt/bin/openwrt/40-dns.sh                /usr/local/share/vmconfig/vm.d/40-dns.sh && \
    ln -s /opt/bin/openwrt/50-set-ips.sh            /usr/local/share/vmconfig/vm.d/50-set-ips.sh && \
    ln -s /opt/bin/openwrt/serialize-vm-config.sh   /usr/local/bin/serialize-vm-config.sh && \
    ln -s /opt/bin/openwrt/send-config-to-vm.sh     /usr/local/bin/send-config-to-vm.sh && \
    ln -s /opt/bin/openwrt/run-vm.sh                /usr/local/bin/run-vm.sh && \
    ln -s /opt/bin/openwrt/container_net_setup.sh   /usr/local/bin/container_net_setup.sh

WORKDIR /tmp
