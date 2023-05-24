#!/usr/bin/env bash
set -euxo pipefail

SCRIPT_DIR="${SCRIPT_DIR:-$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )}"
source ${SCRIPT_DIR}/../../ci/env.sh
BASE_DIR=$(cd "${SCRIPT_DIR}/../.." >/dev/null 2>&1 && pwd )

REBUILD="true"
if [[ "${1:-}" == "--check-norebuild" && -f "${BASE_DIR}/libtelio/nat-lab/bin/wireguard-go" ]]; then
    REBUILD="false"
fi

if [[ "$REBUILD" == "true" ]]; then
    "${BASE_DIR}/ci/build.sh" --default wireguard-go
fi
