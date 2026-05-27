#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${HERE}/../../../generated/native"
mkdir -p "$OUT"
clang -O2 -target x86_64-apple-darwin -o "${OUT}/stripped_macho" "${HERE}/stripped_macho.c"
strip -S -x "${OUT}/stripped_macho"
file "${OUT}/stripped_macho"
