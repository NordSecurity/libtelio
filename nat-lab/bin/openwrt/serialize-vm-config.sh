#!/bin/sh
set -e
cat <<EOF

echo "require \"nixio\"; io.stdin:setvbuf \"no\"; io.write(nixio.bin.b64decode(io.read()));" > /tmp/base64_decode.lua
lua /tmp/base64_decode.lua > /tmp/vmconfig.tgz
EOF

tar -zcv -C "$1" . | base64 -w0

cat <<EOF

mkdir /tmp/vmconfig
tar -zxvf /tmp/vmconfig.tgz -C /tmp/vmconfig
ls -l /tmp/vmconfig || true
ls -l /tmp/vmconfig/vm.d || echo "!! Directory does not exist after extraction"
sleep 5
if [ -d /tmp/vmconfig/vm.d ]; then
  for f in /tmp/vmconfig/vm.d/*; do
    [ -f "\$f" ] || continue
    echo "Executing \$f"
    sh "\$f" || exit 1
  done
  echo -e "\\nVM configuration result: successful."
else
  echo "No vm.d directory found!"
  echo -e "\\nVM configuration result: failed."
  exit 1
fi
poweroff
EOF
