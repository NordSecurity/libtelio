#!/usr/bin/env bash

set -eux

if [[ $1 == windows ]]; then

    export GOOS=windows
    export GOARCH=amd64
    export CC=x86_64-w64-mingw32-gcc
    export CGO_ENABLED=1

elif [[ $1 == android ]]; then

    export GOOS=android
    export GOARCH=arm64
    export CC=aarch64-linux-android21-clang
    export CGO_ENABLED=1

else 

    echo "ERROR: Target OS $1 not supported"
    exit 1

fi

if [ -z "${CGO_CFLAGS:-}" ]; then
    export CGO_CFLAGS="-D_FORTIFY_SOURCE=2"
else
    export CGO_CFLAGS="$CGO_CFLAGS -D_FORTIFY_SOURCE=2"
fi

echo $OUT_DIR

if [[ $1 == android ]]; then
export PATH=$PATH:/usr/local/go/bin
    go build -ldflags=-w -v -buildmode c-shared -o "$OUT_DIR/libwireguard-go.so" wireguard-go
else
    go build -ldflags=-w -v -buildmode c-archive -o "$OUT_DIR/libwireguard-go.a" wireguard-go
fi

