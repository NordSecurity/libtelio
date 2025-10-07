#!/bin/sh
set -ex
bash container_net_setup.sh

if [ ! -f /var/lib/qemu/initialized ]; then
  timeout -s SIGINT "$QEMU_CONFIG_TIMEOUT" send-config-to-vm.sh
  touch /var/lib/qemu/initialized
  chmod g+rw /var/lib/qemu/*
fi

exec run-vm.sh
