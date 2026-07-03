#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${HERE}/../../../generated/native"
mkdir -p "$OUT"
gcc -O2 -static -s -o "${OUT}/stripped_elf" "${HERE}/stripped_elf.c"
strip --strip-all "${OUT}/stripped_elf"
file "${OUT}/stripped_elf"
