#!/bin/bash

# This is a simple example script on how to use DTCLI to turn off VPN and clean up routing.

# NOTE: This is meant to be run from the libtelio directory.
# And uses the debug build so that you could iterate quicker builds when debugging.

DTCLI_PATH="target/debug/dtcli"

# You may need to change these to your default values.
TUNNEL_NAME="tun10"

# Only Linux is supported at the moment.
if [[ $(uname) != "Linux" ]]; then
    echo "This script is only compatible with Linux."
    exit 1
fi

# Check if the script is being run as root to precent half run scripts.
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run with root privileges."
    exit 13
fi

# Check if the interface exists.
if ! ip link show | grep -q "$TUNNEL_NAME"; then
    echo "Tunnel $TUNNEL_NAME does not exists. Enable VPN before disabling it again."
    exit 1
fi

# Ensure ip is installed.
if ! command -v ip &> /dev/null; then
    echo "iproute2 is required but not found. Please install it."
    exit 1
fi

# Save current external IP to verif that it had changed later.
old_public_ip=$(curl -s ifconfig.me)
echo "Externa IP before enabling VPN: ${old_public_ip}"

# Stop WireGuard.
eval ${DTCLI_PATH} dev stop
# Stop libtelio daemon.
eval ${DTCLI_PATH} quit

# Delete VPN route.
# Routing into tunnel and routing from tunnel to VPN server will be deleted automatically when stopping Wireguard.
ip rule del priority 32111 not from all fwmark 11673110 lookup 73110

# Check if the public IP really changed.
new_public_ip=$(curl -s ifconfig.me)
if [ "$new_public_ip" == "$old_public_ip" ]; then
    echo "Error: Public IP had not been changed!"
    exit 1
fi

echo "Success: External IP after enabling VPN: ${new_public_ip}, you are no longer connected over a VPN."
