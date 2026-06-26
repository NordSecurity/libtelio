#!/bin/sh
# Pull OpenWrt's bzImage out of the x86 ext4-combined image so QEMU -M microvm
# can direct-boot it (microvm has no firmware/BIOS to run the image's GRUB).
# Partition 1 is a small ext2 "kernel" partition holding /boot/vmlinuz; carve it
# out with dd and read the kernel with debugfs (no privileged loop mount, so it
# works inside an unprivileged docker build). LLT-7444.
set -eu

IMAGE="$1"
OUT="$2"

# First partition's start sector and length (numeric fdisk columns are
# Start End Sectors Id; the bootable '*' and unit-suffixed Size are skipped).
read -r START SECTORS <<EOF
$(fdisk -l "$IMAGE" | awk '
    /^Device/ { in_table = 1; next }
    in_table && NF >= 4 {
        n = 0
        for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+$/) a[++n] = $i
        print a[1], a[3]
        exit
    }')
EOF

PART1="$(mktemp)"
dd if="$IMAGE" of="$PART1" bs=512 skip="$START" count="$SECTORS" status=none
debugfs -R "dump /boot/vmlinuz $OUT" "$PART1"
rm -f "$PART1"
test -s "$OUT"
