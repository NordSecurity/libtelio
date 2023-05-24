#!/usr/bin/env bash
set -euxo pipefail

SCRIPT_DIR="${SCRIPT_DIR:-$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )}"
source ${SCRIPT_DIR}/../../ci/env.sh

./natlab.py --restart
