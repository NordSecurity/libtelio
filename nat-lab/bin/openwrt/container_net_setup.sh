#!/usr/bin/env bash
set -Eeuox

ETH_COUNT=$(ls /sys/class/net | grep -E '^eth[0-9]+$' | wc -l)
ADD_ERR="Please add the following setting to your container:"

tuntap="TUN device is missing. $ADD_ERR --device /dev/net/tun"
WAN_IP="10.0.254.14/16"
LAN_IP="192.168.115.254"
LAN_IP_MASK="24"

if [ ! -c /dev/net/tun ]; then
  error "$tuntap" && return 1
fi

find_free_ip() {
  local current_ip="$1"
  local prefix="$2" # CIDR prefix length (e.g., 24)

  # Parse current IP to integer
  IFS='.' read -r a b c d <<<"$current_ip"
  local ip_int=$((((a << 24) + (b << 16) + (c << 8) + d)))

  # Validate/fallback prefix
  if [[ -z "${prefix:-}" ]] || ! [[ "$prefix" =~ ^[0-9]+$ ]] || ((prefix < 1 || prefix > 30)); then
    prefix=$(ip -o -f inet addr show | awk -v ip="$current_ip" '$4 ~ ip"/" {print $4}' | cut -d/ -f2 | head -n1 || true)
    [[ -z "${prefix:-}" ]] && prefix=24
  fi

  # Compute network and broadcast as integers
  local mask_int=$((((0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF)))
  local net_int=$((ip_int & mask_int))
  local bcast_int=$((net_int | (~mask_int & 0xFFFFFFFF)))

  # Usable range: reserve net+1 as gateway, start from net+2
  local start=$((net_int + 2))
  local end=$((bcast_int - 1))
  if ((end <= start)); then
    echo "No free IP found"
    return
  fi

  # Deterministic starting point to avoid races between parallel containers
  local ident="${HOSTNAME:-$(hostname)}:${APP:-}:${ETH_COUNT:-1}"
  local h=$(echo -n "$ident" | md5sum | cut -c1-8)
  local span=$((end - start + 1))
  local offset=$((0x$h % span))
  local candidate=$((start + offset))

  # Avoid picking the current_ip
  if ((candidate == ip_int)); then
    candidate=$((candidate + 1))
    ((candidate > end)) && candidate=$start
  fi

  # Try up to span probes, wrap around if needed
  local tries=0
  while ((tries < span)); do
    local i1=$(((candidate >> 24) & 0xFF))
    local i2=$(((candidate >> 16) & 0xFF))
    local i3=$(((candidate >> 8) & 0xFF))
    local i4=$((candidate & 0xFF))
    local new_ip="$i1.$i2.$i3.$i4"

    if [[ "$new_ip" != "$current_ip" ]] && ! ping -c 1 -W 1 "$new_ip" &>/dev/null; then
      echo "$new_ip"
      return
    fi

    candidate=$((candidate + 1))
    ((candidate > end)) && candidate=$start
    tries=$((tries + 1))
  done

  echo "No free IP found"
}

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
ip addr del "$LAN_IP/$LAN_IP_MASK" dev dockerbridge1

NEW_BRIDGE_IP=$(find_free_ip "$LAN_IP" "$LAN_IP_MASK")
ip addr add "$NEW_BRIDGE_IP/$LAN_IP_MASK" dev dockerbridge1

ip link set dockerbridge0 down
ip link set dockerbridge0 up
ip link set dockerbridge1 down
ip link set dockerbridge1 up
