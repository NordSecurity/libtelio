FROM ubuntu:24.04

COPY target/release/teliod /usr/local/bin/teliod

# Ensure the binary was copied
RUN test -f /usr/local/bin/teliod && echo "Binary teliod exists" || (echo "ERROR: teliod binary is missing" && exit 1)

RUN chmod +x /usr/local/bin/teliod
