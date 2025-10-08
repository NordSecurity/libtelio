#!/bin/sh
set -ex

rm -f /tmp/qemu-monitor.sock /tmp/qemu-console.sock /tmp/qmp.sock /tmp/qga.sock

exec /usr/bin/qemu-system-x86_64 \
    -nodefaults \
    -display none \
    -m 256M \
    -smp 2 \
    -netdev tap,id=hostnet0,ifname=qemu1,script=no,downscript=no \
    -netdev tap,id=hostnet1,ifname=qemu0,script=no,downscript=no \
    -device virtio-net-pci,romfile=,netdev=hostnet0,mac=52:54:9B:96:1F:00,id=net0 \
    -device virtio-net-pci,romfile=,netdev=hostnet1,mac=52:54:9B:96:1F:01,id=net1 \
    -chardev socket,id=chr0,path=/tmp/qemu-console.sock,mux=on,signal=off,server=on,wait=off \
    -serial chardev:chr0 \
    -monitor unix:/tmp/qemu-monitor.sock,server=on,wait=off \
    -qmp unix:/tmp/qmp.sock,server=on,wait=off \
    -drive file=/var/lib/qemu/image.raw,format=raw,if=virtio \
