ARG LIBTELIO_ENV_SEC_CONTAINER_REGISTRY
ARG LIBTELIO_ENV_NAT_LAB_DEPS_TAG

FROM ${LIBTELIO_ENV_SEC_CONTAINER_REGISTRY}/low-level-hacks/vpn/client/libtelio-build/natlab-deps-common:${LIBTELIO_ENV_NAT_LAB_DEPS_TAG}
LABEL org.opencontainers.image.authors="info@nordsec.com"

COPY --chmod=0755 bin/ /opt/bin/
COPY --chmod=0755 data/custom_debs /opt/custom_debs

# If custom deb is found, install it. This command doesn't fail if it doesn't find anything.
# Useful for overriding prebaked binaries, such as nordderper.
RUN find /opt/custom_debs -name "*.deb" -exec dpkg -i {} \;
RUN \
    tar -xf /opt/tclis-3.6.tar && \
    mv tcli-3.6* /opt/bin/ && \
    chmod +x /opt/bin/tcli*
