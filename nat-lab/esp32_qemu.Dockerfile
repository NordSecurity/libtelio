FROM ghcr.io/nordsecurity/qemu-esp32:v1.0.0

COPY --chmod=0755 bin/ /opt/bin/
