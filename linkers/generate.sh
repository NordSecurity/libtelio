#!/usr/bin/env bash

# Create endpoint exposing linkers
LINKERS=(
	"aarch64-linux-android21-clang"
	"armv7a-linux-androideabi21-clang"
	"x86_64-linux-android21-clang"
	"i686-linux-android21-clang"
)

for i in ${LINKERS[@]}; do
	[ ! -f "d-$i" ] && ln -s dld "d-$i"
done