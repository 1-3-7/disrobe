#!/bin/sh
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
: "${ZIG:=zig}"

build() {
    abi="$1"
    target="$2"
    mkdir -p "$here/lib/$abi"
    for name in antidebug clean; do
        "$ZIG" cc -target "$target" -shared -nostdlib -fPIC -O2 -fno-builtin \
            -Wl,--hash-style=gnu -Wl,-z,max-page-size=4096 \
            -o "$here/lib/$abi/lib$name.so" "$here/$name.c"
    done
}

build arm64-v8a aarch64-linux-android
build x86_64 x86_64-linux-android

sha256sum "$here"/lib/*/*.so
wc -c "$here"/lib/*/*.so
