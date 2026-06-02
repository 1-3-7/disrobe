#!/usr/bin/env bash
# regenerate corpus/mac/megafile/EdgeCases.{arm64,x86_64,fat} from src/main.c.
#
# requires a macOS host with the Xcode command-line tools (clang + lipo). on any
# other platform the underlying linker cannot emit Mach-O load commands, so this
# script refuses to run rather than produce a non-Mach-O artifact.
#
# the thin slices (EdgeCases.arm64 / EdgeCases.x86_64) are gitignored because
# they are platform-built & not byte-reproducible across toolchain revisions;
# the fat image (EdgeCases.fat) is the redistributed fixture used by the
# disrobe-pass-swift-objc universal-binary tests.
#
# edge cases exercised by the emitted binaries:
#   - FAT magic (0xcafebabe) wrapping two thin slices via lipo
#   - 64-bit thin Mach-O (MH_MAGIC_64) per arch slice
#   - a non-standard named section (__TEXT,__edge_many) to push the segment /
#     section count past the common-case layout
#   - an __DATA,__objc_imageinfo section (ObjC image-info edge probe)
#   - constructor / destructor load commands (LC_FUNCTION_STARTS surface)
#   - hidden-visibility + external symbols (symbol-table strip edge)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
MEGAFILE="${ROOT}/corpus/mac/megafile"
SRC="${MEGAFILE}/src/main.c"

DRY_RUN=0
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        -h|--help)
            echo "usage: $(basename "$0") [--dry-run]"
            echo "regenerates corpus/mac/megafile/EdgeCases.{arm64,x86_64,fat}"
            exit 0
            ;;
        *)
            echo "unknown arg: $arg" >&2
            exit 2
            ;;
    esac
done

has_cmd() { command -v "$1" >/dev/null 2>&1; }

if [ "$(uname -s)" != "Darwin" ]; then
    echo "error: Mach-O fixtures require a macOS host (uname -s = $(uname -s))" >&2
    echo "       run this script on macOS with the Xcode command-line tools installed." >&2
    exit 3
fi

if ! has_cmd clang || ! has_cmd lipo; then
    echo "error: clang & lipo are required (install: xcode-select --install)" >&2
    exit 3
fi

if [ ! -f "$SRC" ]; then
    echo "error: source not found: $SRC" >&2
    exit 4
fi

ARM64_OUT="${MEGAFILE}/EdgeCases.arm64"
X86_64_OUT="${MEGAFILE}/EdgeCases.x86_64"
FAT_OUT="${MEGAFILE}/EdgeCases.fat"

CFLAGS=(-O1 -fno-omit-frame-pointer -mmacosx-version-min=11.0)

if [ "$DRY_RUN" -eq 1 ]; then
    echo "[plan] clang ${CFLAGS[*]} -arch arm64  -o ${ARM64_OUT} ${SRC}"
    echo "[plan] clang ${CFLAGS[*]} -arch x86_64 -o ${X86_64_OUT} ${SRC}"
    echo "[plan] lipo -create ${ARM64_OUT} ${X86_64_OUT} -output ${FAT_OUT}"
    exit 0
fi

echo "[run] building arm64 slice"
clang "${CFLAGS[@]}" -arch arm64 -o "$ARM64_OUT" "$SRC"

echo "[run] building x86_64 slice"
clang "${CFLAGS[@]}" -arch x86_64 -o "$X86_64_OUT" "$SRC"

echo "[run] fusing universal (fat) image"
lipo -create "$ARM64_OUT" "$X86_64_OUT" -output "$FAT_OUT"

echo "[done] arm64=$(stat -f%z "$ARM64_OUT")B x86_64=$(stat -f%z "$X86_64_OUT")B fat=$(stat -f%z "$FAT_OUT")B"
echo "[note] EdgeCases.fat is committed; the thin slices stay gitignored."
