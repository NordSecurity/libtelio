#!/bin/sh
set -ex
lsblk || true
[ -b /dev/vdb ] && echo "/dev/vdb found" || { echo "/dev/vdb missing!"; exit 1; }
mkdir -p /mnt/usb
echo "Mounting vfat USB..."
mount -t vfat /dev/vdb /mnt/usb && echo "Mount success" || { echo "Mount failed!"; ls /dev; exit 2; }
ls -l /mnt/usb
mkdir -p /etc/ssl/certs
[ -f /mnt/usb/test.pem ] && mv /mnt/usb/test.pem /etc/ssl/certs/ || echo "test.pem not found on USB!"
opkg install /mnt/usb/*.ipk || { echo "opkg install failed!"; umount /mnt/usb; exit 3; }
umount /mnt/usb || echo "Umount failed!"
