#!/bin/sh
set -ex

VM_MAC0="${OPENWRT_VM_MAC0}"
VM_MAC1="${OPENWRT_VM_MAC1}"
QEMU_ARCH="${OPENWRT_QEMU_ARCH}"

rm -f /tmp/qemu-monitor.sock /tmp/qemu-console.sock /tmp/qmp.sock /tmp/qga.sock

case "${QEMU_ARCH}" in
  mipsel)
    exec /usr/bin/qemu-system-mipsel \
        -display none \
        -M malta \
        -kernel /var/lib/qemu-image/vmlinux.elf \
        -m 256M \
        -smp 1 \
        -append "root=/dev/sda console=ttyS0" \
        -netdev tap,id=hostnet0,ifname=qemu1,script=no,downscript=no \
        -netdev tap,id=hostnet1,ifname=qemu0,script=no,downscript=no \
        -device virtio-net-pci,romfile=,netdev=hostnet0,mac=${VM_MAC0},id=net0 \
        -device virtio-net-pci,romfile=,netdev=hostnet1,mac=${VM_MAC1},id=net1 \
        -serial chardev:chr0 \
        -chardev socket,id=chr0,path=/tmp/qemu-console.sock,mux=on,signal=off,server=on,wait=off \
        -monitor unix:/tmp/qemu-monitor.sock,server=on,wait=off \
        -qmp unix:/tmp/qmp.sock,server=on,wait=off \
        -drive file=/var/lib/qemu/image.raw,format=raw,if=ide
    ;;
  x86_64)
    # Use hardware acceleration when /dev/kvm is usable; otherwise fall back to
    # TCG software emulation (e.g. CI runners without nested virt). KVM is both
    # much faster and lighter on host CPU than TCG.
    if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
        ACCEL_ARGS="-enable-kvm -cpu host"
    else
        ACCEL_ARGS="-cpu max"
    fi
    exec /usr/bin/qemu-system-x86_64 \
        -nodefaults \
        -display none \
        ${ACCEL_ARGS} \
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
    echo "OPENWRT_QEMU_ARCH must be set to 'x86_64' or 'mipsel' (got: '${QEMU_ARCH}')" >&2
    exit 1
    ;;
esac
