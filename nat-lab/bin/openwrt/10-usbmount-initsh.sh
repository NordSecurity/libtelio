#!/bin/sh
cat <<'EOUSB' > /etc/init.d/usbmount
#!/bin/sh /etc/rc.common
START=89
start() {
  mkdir -p /mnt/usb
  if ! mount | grep -q "/mnt/usb"; then
    [ -b /dev/vdb ] && mount -t vfat /dev/vdb /mnt/usb || true
  fi
}
EOUSB
chmod +x /etc/init.d/usbmount
/etc/init.d/usbmount enable
