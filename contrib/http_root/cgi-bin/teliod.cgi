#!/usr/bin/env bash

set -eu -o pipefail

fail() {
  cat $DEV_DIR/cargo.log
  exit 0
}

DEV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$(realpath $DEV_DIR/../../../target/debug/)"

export BYPASS_LLT_SECRETS=1
BUILD_USER=${SUDO_USER:-$(cat $DEV_DIR/builder)}

sudo --preserve-env=BYPASS_LLT_SECRETS -u $BUILD_USER -- cargo build -F cgi -p teliod >"$DEV_DIR/cargo.log" 2>&1 || fail

export PATH=$BIN_DIR:$PATH

exec teliod cgi
