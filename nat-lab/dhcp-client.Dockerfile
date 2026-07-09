# A nat-lab client that obtains its address via DHCP, unlike the nat-lab:base clients which
# are statically addressed. Reusable for tests that exercise DHCP behaviour - e.g. an OpenWRT
# LAN client picking up the VPN MTU advertised via DHCP option 26 (LLT-6852).
FROM nat-lab:base
LABEL org.opencontainers.image.authors="info@nordsec.com"
LABEL org.opencontainers.image.source="https://github.com/NordSecurity/libtelio/blob/main/nat-lab/dhcp-client.Dockerfile"

COPY --chmod=0755 bin/ /opt/bin/

RUN apt-get update \
    && apt-get install -y --no-install-recommends busybox \
    && rm -rf /var/lib/apt/lists/*
