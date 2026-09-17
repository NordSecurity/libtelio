#!/bin/sh
set -ex

# Validate required environment variables.
# All OpenWrt GW containers must set these in docker-compose.yml.
missing=""
for var in OPENWRT_WAN_IP OPENWRT_LAN_BRIDGE_IP OPENWRT_VM_LAN_IP \
           OPENWRT_VM_WAN_IP OPENWRT_VM_MAC0 OPENWRT_VM_MAC1; do
  eval val=\$$var
  if [ -z "$val" ]; then
    missing="$missing $var"
  fi
done
if [ -n "$missing" ]; then
  echo "ERROR: Missing required environment variables:$missing"
  echo "Set them in the docker-compose.yml environment block for this container."
  exit 1
fi

bash container_net_setup.sh

# Generate VM environment config from container env vars.
# This file is packed into the vmconfig tarball and can be sourced
# by VM scripts (e.g. 50-set-ips.sh) since each script runs in its
# own shell and doesn't inherit container env vars.
cat > /var/lib/vmconfig/vm.d/05-vm-env.conf <<EOF
OPENWRT_VM_LAN_IP="${OPENWRT_VM_LAN_IP}"
OPENWRT_VM_WAN_IP="${OPENWRT_VM_WAN_IP}"
EOF

if [ ! -f /var/lib/qemu/initialized ]; then
  timeout -s SIGINT "$QEMU_CONFIG_TIMEOUT" send-config-to-vm.sh
  touch /var/lib/qemu/initialized
  chmod g+rw /var/lib/qemu/*
fi

exec run-vm.sh
