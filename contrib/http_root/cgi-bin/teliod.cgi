#!/usr/bin/env bash

set -eu -o pipefail

fail() {
  cat $DEV_DIR/cargo.log
  exit 0
}

DEV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$(realpath $DEV_DIR/../../../target/debug/)"

cargo build -F cgi -p teliod >"$DEV_DIR/cargo.log" 2>&1 || fail

export PATH=$BIN_DIR:$PATH

exec teliod cgi
