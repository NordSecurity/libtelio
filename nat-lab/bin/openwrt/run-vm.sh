#!/bin/sh
set -ex
exec /usr/bin/qemu-system-x86_64 \
    -nodefaults \
    -display none \
    -m 256M \
    -smp 2 \
    -nic "user,model=virtio,restrict=on,ipv6=off,net=192.168.1.0/24,host=192.168.1.2" \
    -nic "user,model=virtio,net=172.16.0.0/24,hostfwd=tcp::30022-:22,hostfwd=tcp::30080-:80,hostfwd=tcp::30443-:443" \
    -chardev socket,id=chr0,path=/tmp/qemu-console.sock,mux=on,logfile=/dev/stdout,signal=off,server=on,wait=off \
    -serial chardev:chr0 \
    -monitor unix:/tmp/qemu-monitor.sock,server,nowait \
    -drive file=/var/lib/qemu/image.raw,if=virtio \
    -drive file=/var/lib/qemu-image/ipks.img,if=virtio
