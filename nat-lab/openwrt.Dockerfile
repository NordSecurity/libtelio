ARG LIBTELIO_ENV_SEC_CONTAINER_REGISTRY

FROM ${LIBTELIO_ENV_SEC_CONTAINER_REGISTRY}/low-level-hacks/third-party-build/openwrt_image/natlab-openwrt-24.10.2-x86-64:v0.0.1

ENV QEMU_CONFIG_TIMEOUT="300"

COPY --chmod=0755 bin/ /opt/bin/

WORKDIR /ipk-source
COPY bin/nordvpnlite_x86_64.ipk /ipk-source/
COPY data/core_api/test.pem /ipk-source/

RUN mkdir -p /var/lib/qemu-image
WORKDIR /var/lib/qemu-image

RUN mkdir -p /var/lib/qemu && \
    gunzip -c openwrt-24.10.2-x86-64-generic-ext4-combined.img.gz > /var/lib/qemu/image.raw

RUN dd if=/dev/zero of=ipks.img bs=1M count=100 && \
    mformat -i ipks.img :: && \
    mcopy -i ipks.img /ipk-source/*.ipk :: && \
    mcopy -i ipks.img /ipk-source/test.pem ::

RUN mkdir -p /usr/local/share/vmconfig/container.d /usr/local/share/vmconfig/vm.d
RUN mkdir -p /var/lib/vmconfig/container.d /var/lib/vmconfig/vm.d

RUN ln -s /opt/bin/openwrt/10-usbmount-initsh.sh    /usr/local/share/vmconfig/vm.d/10-usbmount-initsh.sh && \
    ln -s /opt/bin/openwrt/20-firewall.sh           /usr/local/share/vmconfig/vm.d/20-firewall.sh && \
    ln -s /opt/bin/openwrt/30-wait-for-network.sh   /usr/local/share/vmconfig/vm.d/30-wait-for-network.sh && \
    ln -s /opt/bin/openwrt/40-dns.sh                /usr/local/share/vmconfig/vm.d/40-dns.sh && \
    ln -s /opt/bin/openwrt/50-set-ips.sh            /usr/local/share/vmconfig/vm.d/50-set-ips.sh && \
    ln -s /opt/bin/openwrt/99-install-ipks.sh       /usr/local/share/vmconfig/vm.d/99-install-ipks.sh && \
    ln -s /opt/bin/openwrt/serialize-vm-config.sh   /usr/local/bin/serialize-vm-config.sh && \
    ln -s /opt/bin/openwrt/send-config-to-vm.sh     /usr/local/bin/send-config-to-vm.sh && \
    ln -s /opt/bin/openwrt/run-vm.sh                /usr/local/bin/run-vm.sh && \
    ln -s /opt/bin/openwrt/entrypoint.sh            /usr/local/bin/entrypoint.sh && \
    ln -s /opt/bin/openwrt/container_net_setup.sh   /usr/local/bin/container_net_setup.sh

HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD \
ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=3 root@192.168.115.254 'exit' || exit 1

WORKDIR /tmp

CMD ["/usr/local/bin/entrypoint.sh"]
