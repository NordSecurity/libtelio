FROM ubuntu:24.04

COPY target/release/nordvpnlite /usr/local/bin/nordvpnlite

# Ensure the binary was copied
RUN test -f /usr/local/bin/nordvpnlite && echo "Binary nordvpnlite exists" || (echo "ERROR: nordvpnlite binary is missing" && exit 1)

RUN chmod +x /usr/local/bin/nordvpnlite
