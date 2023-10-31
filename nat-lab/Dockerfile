ARG LIBTELIO_ENV_SEC_CONTAINER_REGISTRY
ARG LIBTELIO_ENV_NAT_LAB_DEPS_TAG

FROM ${LIBTELIO_ENV_SEC_CONTAINER_REGISTRY}/low-level-hacks/vpn/client/libtelio-build/natlab-deps-common:${LIBTELIO_ENV_NAT_LAB_DEPS_TAG}
LABEL org.opencontainers.image.authors="info@nordsec.com"

COPY --chmod=0755 bin/ /opt/bin/
RUN \
    tar -xf /opt/tclis-3.6.tar && \
    mv tcli-3.6* /opt/bin/ && \
    chmod +x /opt/bin/tcli*
