#!/bin/sh
set -ex
bash container_net_setup.sh

# Generate VM environment config from container env vars.
# This file is packed into the vmconfig tarball and can be sourced
# by VM scripts (e.g. 50-set-ips.sh) since each script runs in its
# own shell and doesn't inherit container env vars.
cat > /var/lib/vmconfig/vm.d/05-vm-env.conf <<EOF
OPENWRT_VM_LAN_IP="${OPENWRT_VM_LAN_IP:-192.168.115.254}"
OPENWRT_VM_WAN_IP="${OPENWRT_VM_WAN_IP:-10.0.0.2}"
EOF

if [ ! -f /var/lib/qemu/initialized ]; then
  timeout -s SIGINT "$QEMU_CONFIG_TIMEOUT" send-config-to-vm.sh
  touch /var/lib/qemu/initialized
  chmod g+rw /var/lib/qemu/*
fi

exec run-vm.sh
