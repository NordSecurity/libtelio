#!/bin/sh

set -eu

OPENWRT_GW_IP=192.168.115.254

[ -S /tmp/qmp.sock ] || exit 1

OUT=$(
  { printf '%s\n' \
      '{ "execute": "qmp_capabilities" }' \
      '{ "execute": "query-status" }' \
    | socat - UNIX-CONNECT:/tmp/qmp.sock; } 2>/dev/null || true
)

echo "$OUT" | grep -q '"status"\s*:\s*"running"' || exit 1

if [ -S /tmp/qga.sock ]; then
  GAP=$(
    { printf '%s\n' \
        '{ "execute": "qmp_capabilities" }' \
        '{ "execute": "guest-ping" }' \
      | socat - UNIX-CONNECT:/tmp/qmp.sock; } 2>/dev/null || true
  )
  echo "$GAP" | grep -q '"return"\s*:\s*{}' || exit 1
fi

[ -f /var/lib/qemu/initialized ] || exit 1


socat -T 2 - tcp:"$OPENWRT_GW_IP":22,connect-timeout=2 </dev/null >/dev/null 2>&1 || exit 1

exit 0
