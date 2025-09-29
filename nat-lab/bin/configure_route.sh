#!/usr/bin/env bash
set -euxo pipefail

trap - ERR

print_help() {
    echo "Usage: ./configure_route.sh <primary|secondary> [linux|windows|mac]"
    exit 1
}

OS_TYPE="${2:-linux}"

case "${1:-}" in
primary)
    case "$OS_TYPE" in
    linux)
        if [[ $CLIENT_GATEWAY_PRIMARY != "none" ]]; then
            ip route delete 10.0.0.0/16 || true
            ip route add 10.0.0.0/16 via $CLIENT_GATEWAY_PRIMARY dev eth0

            if [[ -n ${INTERMEDIATE_NETWORK:-} ]]; then
                ip route delete $INTERMEDIATE_NETWORK || true
                ip route add $INTERMEDIATE_NETWORK via $CLIENT_GATEWAY_PRIMARY dev eth0
            fi
        fi
        ;;
    windows)
        python3 /run/qga.py route delete 0.0.0.0
        if [[ $? -ne 0 ]]; then
            echo "Failed to delete route using qga.py" >&2
            exit 2
        fi

        python3 /run/qga.py powershell -Command "New-NetRoute -DestinationPrefix '0.0.0.0/0' -NextHop '$CLIENT_GATEWAY_PRIMARY' -InterfaceAlias 'Ethernet'"
        if [[ $? -ne 0 ]]; then
            echo "Failed to add new route using qga.py" >&2
            exit 2
        fi
        ;;
    mac)
        python3 /run/qga.py --sh "route delete default || true"
        python3 /run/qga.py --sh "route add default '$CLIENT_GATEWAY_PRIMARY'"
        ;;
    *)
        echo "Invalid OS type '${OS_TYPE}'"
        print_help
        exit 1
        ;;
    esac
    ;;
secondary)
    case "$OS_TYPE" in
    linux)
        ip route delete 10.0.0.0/16 || true
        ip route add 10.0.0.0/16 via $CLIENT_GATEWAY_SECONDARY dev eth1
        ;;
    windows)
        python3 /run/qga.py route delete 0.0.0.0
        if [[ $? -ne 0 ]]; then
            echo "Failed to delete route using qga.py" >&2
            exit 2
        fi

        python3 /run/qga.py powershell -Command "New-NetRoute -DestinationPrefix '0.0.0.0/0' -NextHop '$CLIENT_GATEWAY_SECONDARY' -InterfaceAlias 'Ethernet 2'"
        if [[ $? -ne 0 ]]; then
            echo "Failed to add new route using qga.py" >&2
            exit 2
        fi
        ;;
    mac)
        python3 /run/qga.py --sh "route delete default || true"
        python3 /run/qga.py --sh "route add default '$CLIENT_GATEWAY_SECONDARY'"
        ;;
    *)
        echo "Invalid OS type '${OS_TYPE}'"
        print_help
        exit 1
        ;;
    esac
    ;;
*)
    echo "Unrecognized parameter '${1:-}'"
    print_help
    exit 1
    ;;
esac
