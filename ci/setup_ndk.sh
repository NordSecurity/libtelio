#!/bin/bash

set -euxo pipefail

mkdir -p "./source/.build"

export ANDROIDNDK="$(readlink -e ./source/.build)"
export BUILDOS="linux"
export NDKVERSION="r26"
export NDKZIPNAME="android-ndk-$NDKVERSION-$BUILDOS.zip"
export NDKZIP="https://dl.google.com/android/repository/$NDKZIPNAME"
export TOOLCHAIN="$ANDROIDNDK/android-ndk-$NDKVERSION/toolchains/llvm/prebuilt/linux-x86_64"

echo "ANDROIDNDK: ${ANDROIDNDK}"

curl -SLO "$NDKZIP"
mv "$NDKZIPNAME" "$ANDROIDNDK/"
unzip "$ANDROIDNDK/$NDKZIPNAME" -d "$ANDROIDNDK"
rm -f "$ANDROIDNDK/$NDKZIPNAME"

# For crate get_if_addr-sys
ln -s "$TOOLCHAIN/bin/x86_64-linux-android21-clang"     "$TOOLCHAIN/bin/x86_64-linux-android-gcc"
ln -s "$TOOLCHAIN/bin/i686-linux-android21-clang"       "$TOOLCHAIN/bin/i686-linux-android-gcc"
ln -s "$TOOLCHAIN/bin/aarch64-linux-android21-clang"    "$TOOLCHAIN/bin/aarch64-linux-android-gcc"
ln -s "$TOOLCHAIN/bin/armv7a-linux-androideabi21-clang" "$TOOLCHAIN/bin/arm-linux-androideabi-gcc"
ln -s "$TOOLCHAIN/bin/armv7a-linux-androideabi21-clang" "$TOOLCHAIN/bin/arm7a-linux-androideabi-gcc"


ln -s "$TOOLCHAIN/bin/llvm-ar" "$TOOLCHAIN/bin/x86_64-linux-android-ar"
ln -s "$TOOLCHAIN/bin/llvm-ar" "$TOOLCHAIN/bin/i686-linux-android-ar"
ln -s "$TOOLCHAIN/bin/llvm-ar" "$TOOLCHAIN/bin/aarch64-linux-android-ar"
ln -s "$TOOLCHAIN/bin/llvm-ar" "$TOOLCHAIN/bin/arm-linux-androideabi-ar"
ln -s "$TOOLCHAIN/bin/llvm-ar" "$TOOLCHAIN/bin/arm7a-linux-androideabi-ar"

echo "$ANDROIDNDK/android-ndk-r26/toolchains/llvm/prebuilt/linux-x86_64/bin" >> $GITHUB_PATH
