ARG CONTAINER_REGISTRY
ARG NAT_LAB_DEPS_TAG

FROM ${CONTAINER_REGISTRY}/low-level-hacks/vpn/client/libtelio-build/natlab-deps-common:${NAT_LAB_DEPS_TAG}
LABEL org.opencontainers.image.authors="info@nordsec.com"

COPY --chmod=0755 bin/ /opt/bin/
COPY data/wg0.conf /
COPY data/nordderper.deb /tmp/

# well.... I do not know nftables yet... somebody please teach me.
RUN update-alternatives --set iptables /usr/sbin/iptables-legacy
RUN \
    dpkg --unpack /tmp/nordderper.deb && \
    rm /var/lib/dpkg/info/nordderper.postinst && \
    dpkg --configure nordderper && \
    DEBIAN_FRONTEND=noninteractive apt-get install -yf && \
    rm -f /tmp/nordderper.deb && \
    DEBIAN_FRONTEND=noninteractive apt-get clean
