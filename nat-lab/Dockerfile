ARG CONTAINER_REGISTRY
ARG NAT_LAB_DEPS_TAG

FROM ${CONTAINER_REGISTRY}/low-level-hacks/vpn/client/libtelio-build/natlab-deps-common:${NAT_LAB_DEPS_TAG}
LABEL org.opencontainers.image.authors="info@nordsec.com"

COPY --chmod=0755 bin/ /opt/bin/
