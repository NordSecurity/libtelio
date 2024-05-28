#!/bin/bash

# This is a simple example script on how to use TCLID to set up VPN.

# NOTE: This is meant to be run from the libtelio directory.
# Also it assumes that your nord token is in the $NORD_TOKEN variable. So also make sure to run it with `sudo -E`.
# And uses the debug build so that you could iterate quicker builds when debugging.

# This script takes a single argument which is the name of the tunnel for Telio to use.
if [ $# -eq 0 ]; then
    echo "No tunnel name provided, using tun10 as default."
    TUNNEL_NAME="tun10"
else
    TUNNEL_NAME=$1
fi

TCLID_PATH="target/debug/tclid"

# Below are a few checks to make sure that the environment is correct for this script to run and not mess up the network configuration:
# If it does mess up the network configuration, you can just restart your PC ;)

# Only Linux is supported at the moment.
if [[ $(uname) != "Linux" ]]; then
    echo "This script is only compatible with Linux."
    exit 126
fi

# Ensure curl is installed.
if ! command -v curl &> /dev/null; then
    echo "curl is required but not found. Please install it."
    exit 127
fi

# Ensure jq is installed.
if ! command -v jq &> /dev/null; then
    echo "jq is required but not found. Please install it."
    exit 127
fi

# Ensure ip is installed.
if ! command -v ip &> /dev/null; then
    echo "iproute2 is required but not found. Please install it."
    exit 127
fi

if ! [ -f "$TCLID_PATH" ]; then
    echo "Cannot find TCLID in $TCLID_PATH directory. Please build TCLID and run it from libtelio root."
    exit 127
fi

# Function to validate NORD_TOKEN
validate_nord_token() {
    local token="$1"
    if [[ ! "$token" =~ ^[[:alnum:]]{64}$ ]]; then
        echo "Error: Invalid NORD_TOKEN. It must be a 64-character-long alphanumeric string."
        return 1
    fi
}

# Check if the script is being run as root to precent half run scripts.
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: This script must be run with root privileges."
    exit 13
fi

# Check if the NORD_TOKEN variable is set
if [ -z "$NORD_TOKEN" ]; then
    echo "NORD_TOKEN variable is not set."
    read -p "Please enter your NORD_TOKEN or run this script with \`sudo -E\`: " NORD_TOKEN
fi

# Validate the entered NORD_TOKEN
if ! validate_nord_token "$NORD_TOKEN"; then
    exit 1
fi

# Below is the actual libtelio usage:

# Check if the interface already exists.
if ip link show | grep -q "$TUNNEL_NAME"; then
    echo "Tunnel $TUNNEL_NAME already exists. Disable VPN before enabling it again."
    exit 1
fi

# Save current external IP to verif that it had changed later.
old_public_ip=$(curl -s ifconfig.me)
echo "External IP before enabling VPN: ${old_public_ip}"

# Starting WireGuard.
eval ${TCLID_PATH} dev start boringtun ${TUNNEL_NAME}

# Getting VPN server IP and public key.
recommended_servers_list=$(curl -s "https://api.nordvpn.com/v1/servers/recommendations?&filters\[servers_technologies\]\[identifier\]=wireguard_udp&limit=1" -u token:$NORD_TOKEN)
recommended_server_public_key=$(echo ${recommended_servers_list} | jq --raw-output '.[].technologies[]|select(.identifier == "wireguard_udp")|.metadata[].value')
recommended_server_ip=$(echo ${recommended_servers_list} | jq --raw-output '.[].station')

# Configuring interface.
ip addr add dev ${TUNNEL_NAME} 10.5.0.2/10
ip link set up dev ${TUNNEL_NAME}
ip link set dev ${TUNNEL_NAME} mtu 1420

# Connecting to VPN.
eval ${TCLID_PATH} dev con ${recommended_server_public_key} ${recommended_server_ip}:51820

# Creating VPN route.
ip route add default dev ${TUNNEL_NAME} table 73110
ip route add ${recommended_server_ip} dev ${TUNNEL_NAME} table 73110
ip rule add not from all fwmark 11673110 lookup 73110

# Check if the public IP really changed.
new_public_ip=$(curl -s ifconfig.me)
if [ "$new_public_ip" == "$old_public_ip" ]; then
    echo "Error: Public IP had not been changed!"
    exit 1
fi

echo "Success: External IP after enabling VPN: ${new_public_ip}, you are now connected over a VPN."
