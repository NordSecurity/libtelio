#!/bin/sh
set -ex
if [ ! -f /var/lib/qemu/initialized ]; then
    timeout -s SIGINT "$QEMU_CONFIG_TIMEOUT" send-config-to-vm.sh || (echo "VM config error or time out."; exit 1)
    touch /var/lib/qemu/initialized
    chmod g+rw /var/lib/qemu/*
fi
exec run-vm.sh
