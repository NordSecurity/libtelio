#!/bin/sh

set -eu

OPENWRT_GW_IP=${OPENWRT_VM_LAN_IP}
SSH_TIMEOUT=20

[ -S /tmp/qmp.sock ] || exit 1

OUT=$(
  { printf '%s\n' \
      '{ "execute": "qmp_capabilities" }' \
      '{ "execute": "query-status" }' \
    | socat - UNIX-CONNECT:/tmp/qmp.sock; } 2>/dev/null || true
)

echo "$OUT" | grep -q '"status"\s*:\s*"running"' || exit 1

[ -f /var/lib/qemu/initialized ] || exit 1

printf 'SSH-2.0-natlab_healthcheck\r\n' \
  | socat -t "$SSH_TIMEOUT" -T "$SSH_TIMEOUT" - \
      tcp:"$OPENWRT_GW_IP":22,connect-timeout="$SSH_TIMEOUT" 2>/dev/null \
  | grep -q '^SSH-2\.0-' \
  || { echo "no SSH identification from $OPENWRT_GW_IP:22"; exit 1; }

exit 0
