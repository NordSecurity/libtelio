#!/usr/bin/env bash
set -euxo pipefail

# Enable NAT to allow other VMs (`windows`, `mac`) to communicate with Docker
# network (10.0.0.0/16) running on `default` VM. Also, this NAT serves as a gateway
# to internet for other VMs, since the default route is changed to simulate an actual
# VPN application (`windows_vm_util.py::_create_gateway_route_to_linux`,
# `mac_vm_util.py::_create_gateway_route_to_linux`).

print_help() {
    echo "Usage: ./vm_nat.sh <enable|disable>"
    exit 1
}

# Arbitraty IDs
PRIMARY_TABLE=2221
SECONDARY_TABLE=2222

# Same as declared in Vagrantfile
VM_PRIMARY_NETWORK="10.55.0.0/24"
VM_SECONDARY_NETWORK="10.66.0.0/24"

# Same as declared in docker-compose.yml
DOCKER_NETWORK="10.0.0.0/16"
DOCKER_PRIMARY_GATEWAY="192.168.107.254"
DOCKER_SECONDARY_GATEWAY="192.168.108.254"

case "${1:-}" in
    enable)
        ip rule add from $VM_PRIMARY_NETWORK table $PRIMARY_TABLE
        ip route add $DOCKER_NETWORK via $DOCKER_PRIMARY_GATEWAY table $PRIMARY_TABLE

        ip rule add from $VM_SECONDARY_NETWORK table $SECONDARY_TABLE
        ip route add $DOCKER_NETWORK via $DOCKER_SECONDARY_GATEWAY table $SECONDARY_TABLE
        ;;
    disable)
        ip route delete $DOCKER_NETWORK table $PRIMARY_TABLE || true
        ip route delete $DOCKER_NETWORK table $SECONDARY_TABLE || true
        ;;
    *)
        echo "Unrecognized parameter '${1:-}'"
        print_help
esac
