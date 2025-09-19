#!/bin/sh
set -ex
find /var/lib/vmconfig
rm -rf /tmp/vmconfig
cp -rv /var/lib/vmconfig /tmp/vmconfig
mkdir -p /tmp/vmconfig/container.d /tmp/vmconfig/vm.d
if [ "$(ls -A /usr/local/share/vmconfig/container.d)" ]; then
    cp /usr/local/share/vmconfig/container.d/* /tmp/vmconfig/container.d
fi
if [ "$(ls -A /usr/local/share/vmconfig/vm.d)" ]; then
    cp /usr/local/share/vmconfig/vm.d/* /tmp/vmconfig/vm.d
fi
(cd /tmp/vmconfig && (for f in $(ls container.d); do "./container.d/$f"; done))
run-vm.sh &
QEMU_PID="$!"
sleep 2
echo "Files in /tmp directory"
ls -l /tmp
for i in $(seq 1 10); do
  if [ -S /tmp/qemu-console.sock ]; then break; fi
  sleep 0.5
done
if [ ! -S /tmp/qemu-console.sock ]; then
  echo "Socket never appeared."
  exit 1
fi
timeout 30s socat -d -d -u UNIX-CONNECT:/tmp/qemu-console.sock - | grep -q "Please press Enter to activate this console."
echo | socat -d -d -u - UNIX-CONNECT:/tmp/qemu-console.sock
serialize-vm-config.sh /tmp/vmconfig | socat -d -d STDIN unix-connect:/tmp/qemu-console.sock
VM_CONFIG_RESULT="$(socat STDOUT unix-connect:/tmp/qemu-console.sock | grep -m1 "^VM configuration result:")"
if test "${VM_CONFIG_RESULT#*failed}" != "$VM_CONFIG_RESULT"; then
    exit 1
fi
wait "$QEMU_PID"

