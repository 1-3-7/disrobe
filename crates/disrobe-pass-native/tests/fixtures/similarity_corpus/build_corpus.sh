#!/bin/sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
out=${1:-"$here/out"}
mkdir -p "$out"

gcc_bin=${CC_GCC:-gcc}
clang_bin=${CC_CLANG:-clang}
strip_bin=${STRIP:-strip}

hosted="$here/harness_hosted.c"
freestanding="$here/harness_free.c"

have() {
    command -v "$1" >/dev/null 2>&1
}

build() {
    name=$1
    source=$2
    harness=$3
    shift 3
    if [ -f "$out/$name" ]; then
        return 0
    fi
    "$@" -o "$out/$name" "$source" "$harness" || return 1
    cp "$out/$name" "$out/$name.stripped"
    "$strip_bin" -s "$out/$name.stripped" || rm -f "$out/$name.stripped"
}

for source in "$here"/*.c; do
    base=$(basename "$source" .c)
    case "$base" in
        harness_*) continue ;;
    esac
    echo "building $base"

    if have "$gcc_bin"; then
        build "$base.gcc.pe.O0.exe" "$source" "$hosted" \
            "$gcc_bin" -I"$here" -O0 || echo "  skip gcc -O0"
        build "$base.gcc.pe.O2.exe" "$source" "$hosted" \
            "$gcc_bin" -I"$here" -O2 || echo "  skip gcc -O2"
    fi

    if have "$clang_bin"; then
        build "$base.clang.pe.O2.exe" "$source" "$hosted" \
            "$clang_bin" -I"$here" --target=x86_64-w64-windows-gnu -O2 || echo "  skip clang pe"
        for level in O0 Os O2; do
            build "$base.clang.elf64.$level.elf" "$source" "$freestanding" \
                "$clang_bin" -I"$here" --target=x86_64-unknown-linux-gnu -nostdlib \
                -ffreestanding -fuse-ld=lld "-$level" || echo "  skip clang elf64 -$level"
            build "$base.clang.aarch64.$level.elf" "$source" "$freestanding" \
                "$clang_bin" -I"$here" --target=aarch64-unknown-linux-gnu -nostdlib \
                -ffreestanding -fuse-ld=lld "-$level" || echo "  skip clang aarch64 -$level"
        done
    fi
done

echo "corpus written to $out"
