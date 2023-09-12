#!/usr/bin/env bash
set -euxo pipefail

print_help() {
    echo "Usage: ./configure_route.sh <primary|secondary>"
    exit 1
}

case "${1:-}" in
    primary)
        if [[ $CLIENT_GATEWAY_PRIMARY != "none" ]]; then
            ip route delete 10.0.0.0/16 || true
            ip route add 10.0.0.0/16 via $CLIENT_GATEWAY_PRIMARY dev eth0

            if [[ -n ${INTERMEDIATE_NETWORK:-} ]]; then
                ip route delete $INTERMEDIATE_NETWORK || true
                ip route add $INTERMEDIATE_NETWORK via $CLIENT_GATEWAY_PRIMARY dev eth0
            fi
        fi
        ;;
    secondary)
        ip route delete 10.0.0.0/16 || true
        ip route add 10.0.0.0/16 via $CLIENT_GATEWAY_SECONDARY dev eth1
        ;;
    *)
        echo "Unrecognized parameter '${1:-}'"
        print_help
esac
