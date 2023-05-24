#!/usr/bin/env bash

set -euxo pipefail

SCRIPT_DIR="${SCRIPT_DIR:-$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )}"
source ${SCRIPT_DIR}/../../ci/env.sh
BASE_DIR=$(cd "${SCRIPT_DIR}/../.." >/dev/null 2>&1 && pwd )

BIN_DIR="${BASE_DIR}/libtelio/nat-lab/data"

REBUILD="true"
if [[ "${1:-}" == "--check-norebuild" && -f "$BIN_DIR/nordderper.deb" ]]; then
    REBUILD="false"
fi

case $(uname -m) in
    x86_64) DERPER_ARCH="amd";;
    aarch64) DERPER_ARCH="arm";;
esac

if [[ "$REBUILD" == "true" ]]; then
    "${BASE_DIR}/ci/build.sh" --default derp
    cp "${BASE_DIR}/3rd-party/nordderper/dist/nordderper_${NORDDERPER_VERSION}-1_${DERPER_ARCH}64.deb" "$BIN_DIR/nordderper.deb"
fi
