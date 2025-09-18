#!/usr/bin/env bash
set -Eeuox

ETH_COUNT=$(ls /sys/class/net | grep -E '^eth[0-9]+$' | wc -l)
ADD_ERR="Please add the following setting to your container:"

tuntap="TUN device is missing. $ADD_ERR --device /dev/net/tun"
WAN_IP="10.0.254.14/16"
LAN_IP="192.168.115.254/24"

if [ ! -c /dev/net/tun ]; then
  error "$tuntap" && return 1
fi

for ((i = 0; i < ETH_COUNT; i++)); do
  DOCKER_BRIDGE="dockerbridge$i"
  NET_DEV="eth$i"
  NET_TAP="qemu$i"
  {
    ip link add dev $DOCKER_BRIDGE type bridge
    rc=$?
  } || :

  if ((rc != 0)); then
    error "Failed to create bridge. $ADD_ERR --cap-add NET_ADMIN" && return 1
  fi

  # We need freshly created bridge to have IP address of the container
  # For this reason we need to migrate IP from eth0 to dockerbridge.
  for addr in $(ip --json addr show dev $NET_DEV | jq -c '.[0].addr_info[] | select(.family == "inet")'); do
    cidr_addr=$(echo $addr | jq -r '[ .local, .prefixlen|tostring] | join("/")')
    if ! ip addr add dev $DOCKER_BRIDGE $cidr_addr; then
      error "Failed to add address for $DOCKER_BRIDGE interface"
      exit 30
    fi
  done

  if ! ip addr flush dev $NET_DEV; then
    error "Failed to clear $NET_DEV interface addresses"
    exit 30
  fi

  while ! ip link set $DOCKER_BRIDGE up; do
    info "Waiting for IP address to become available..."
    sleep 2
  done

  # QEMU Works with taps, set tap to the bridge created
  if ! ip tuntap add dev "$NET_TAP" mode tap; then
    error "$tuntap" && return 1
  fi

  while ! ip link set "$NET_TAP" up promisc on; do
    info "Waiting for TAP to become available..."
    sleep 2
  done

  if ! ip link set dev "$NET_TAP" master $DOCKER_BRIDGE; then
    error "Failed to set IP link!" && return 1
  fi

  if ! ip link set dev "$NET_DEV" master $DOCKER_BRIDGE; then
    error "Failed to attach docker interface to bridge"
  fi
done

# deleting ips from the bridge to avoid ip conflicts
# same ips will be assigned to VM interfaces
ip addr del "$WAN_IP" dev dockerbridge0
ip addr del "$LAN_IP" dev dockerbridge1

ip link set dockerbridge0 down
ip link set dockerbridge0 up
ip link set dockerbridge1 down
ip link set dockerbridge1 up
