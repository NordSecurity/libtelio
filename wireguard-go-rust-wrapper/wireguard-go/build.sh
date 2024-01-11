#!/usr/bin/env bash

set -eux

export GOOS=windows
export GOARCH=amd64
export CC=x86_64-w64-mingw32-gcc
export CGO_ENABLED=1

if [ -z "${CGO_CFLAGS:-}" ]; then
    export CGO_CFLAGS="-D_FORTIFY_SOURCE=2"
else
    export CGO_CFLAGS="$CGO_CFLAGS -D_FORTIFY_SOURCE=2"
fi

echo $OUT_DIR

go build -buildvcs=false -ldflags=-w -v -buildmode c-archive -o "$OUT_DIR/libwireguard-go.a" wireguard-go
