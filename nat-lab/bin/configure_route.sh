#!/usr/bin/env bash
set -euxo pipefail

print_help() {
    echo "Usage: ./configure_route.sh <primary|secondary>"
    exit 1
}

# There are a bunch of nightly failures on new Vagrant runners #13, #14, #15, and #16, e.g.
#
# [2024-03-19 12:47:09] |EXECUTE| docker compose logs internal-symmetric-gw-01
# [2024-03-19 12:47:10] internal-symmetric-gw-01-1  | + case "${1:-}" in
# [2024-03-19 12:47:10] internal-symmetric-gw-01-1  | + ip route delete 10.0.0.0/16
# [2024-03-19 12:47:10] internal-symmetric-gw-01-1  | RTNETLINK answers: No such process
# [2024-03-19 12:47:10] internal-symmetric-gw-01-1  | + true
# [2024-03-19 12:47:10] internal-symmetric-gw-01-1  | + ip route add 10.0.0.0/16 via 192.168.103.254 dev eth1
# [2024-03-19 12:47:10] internal-symmetric-gw-01-1  | Cannot find device "eth1"
#
# Its probably because the new runners have much more powerfull CPUs, and this causes some type
# of race condition somewhere in Docker/Compose. Seems like entrypoint is somehow executed first
# before interfaces have been fully configured. To try and workaround this, allow a little bit of
# time for interfaces to be fully initialized.
wait_for_interface() {
    interface=$1

    for i in {0..10}; do
        if ip a show "$interface" up | grep -q inet; then
            echo "Network interface $interface is up."
            return
        else
            echo "Waiting for network interface $interface to be up..."
            sleep 0.2
        fi
    done

    echo "Timeout reached. Network interface $interface is not up."
    exit 1
}

case "${1:-}" in
    primary)
        if [[ $CLIENT_GATEWAY_PRIMARY != "none" ]]; then
            wait_for_interface eth0

            ip route delete 10.0.0.0/16 || true
            ip route add 10.0.0.0/16 via $CLIENT_GATEWAY_PRIMARY dev eth0

            if [[ -n ${INTERMEDIATE_NETWORK:-} ]]; then
                ip route delete $INTERMEDIATE_NETWORK || true
                ip route add $INTERMEDIATE_NETWORK via $CLIENT_GATEWAY_PRIMARY dev eth0
            fi
        fi
        ;;
    secondary)
        wait_for_interface eth1

        ip route delete 10.0.0.0/16 || true
        ip route add 10.0.0.0/16 via $CLIENT_GATEWAY_SECONDARY dev eth1
        ;;
    *)
        echo "Unrecognized parameter '${1:-}'"
        print_help
esac
