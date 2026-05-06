#!/bin/sh
set -ex

VM_MAC0="${OPENWRT_VM_MAC0}"
VM_MAC1="${OPENWRT_VM_MAC1}"
QEMU_ARCH="${OPENWRT_QEMU_ARCH}"

rm -f /tmp/qemu-monitor.sock /tmp/qemu-console.sock /tmp/qmp.sock /tmp/qga.sock

case "${QEMU_ARCH}" in
  aarch64)
    # ARM's virtio-net-device interface enumeration matches the order
    # in which netdevs are declared (hostnet0->eth0, hostnet1->eth1), so
    # qemu0 maps to the WAN-facing tap and qemu1 to the LAN-facing tap.
    # On x86, virtio-net-pci enumerates interfaces in reverse PCI slot
    # order, so the tap names are swapped to keep the same WAN/LAN
    # assignment inside the guest.
    #
    # Using higher RAM/SMP than x86 because aarch64 on an x86 host runs under
    # full QEMU software emulation (no hardware acceleration).
    exec /usr/bin/qemu-system-aarch64 \
        -nodefaults \
        -display none \
        -M virt \
        -cpu cortex-a53 \
        -m 512M \
        -smp 3 \
        -bios /var/lib/qemu-image/u-boot.bin \
        -netdev tap,id=hostnet0,ifname=qemu0,script=no,downscript=no \
        -netdev tap,id=hostnet1,ifname=qemu1,script=no,downscript=no \
        -device virtio-net-device,netdev=hostnet0,mac=${VM_MAC0},id=net0 \
        -device virtio-net-device,netdev=hostnet1,mac=${VM_MAC1},id=net1 \
        -chardev socket,id=chr0,path=/tmp/qemu-console.sock,mux=on,signal=off,server=on,wait=off \
        -serial chardev:chr0 \
        -monitor unix:/tmp/qemu-monitor.sock,server=on,wait=off \
        -qmp unix:/tmp/qmp.sock,server=on,wait=off \
        -device virtio-blk-device,drive=hd0 \
        -drive file=/var/lib/qemu/image.raw,format=raw,if=none,id=hd0
    ;;
  x86_64)
    exec /usr/bin/qemu-system-x86_64 \
        -nodefaults \
        -display none \
        -m 256M \
        -smp 2 \
        -netdev tap,id=hostnet0,ifname=qemu1,script=no,downscript=no \
        -netdev tap,id=hostnet1,ifname=qemu0,script=no,downscript=no \
        -device virtio-net-pci,romfile=,netdev=hostnet0,mac=${VM_MAC0},id=net0 \
        -device virtio-net-pci,romfile=,netdev=hostnet1,mac=${VM_MAC1},id=net1 \
        -chardev socket,id=chr0,path=/tmp/qemu-console.sock,mux=on,signal=off,server=on,wait=off \
        -serial chardev:chr0 \
        -monitor unix:/tmp/qemu-monitor.sock,server=on,wait=off \
        -qmp unix:/tmp/qmp.sock,server=on,wait=off \
        -drive file=/var/lib/qemu/image.raw,format=raw,if=virtio
    ;;
  *)
    echo "OPENWRT_QEMU_ARCH must be set to 'x86_64' or 'aarch64' (got: '${QEMU_ARCH}')" >&2
    exit 1
    ;;
esac
