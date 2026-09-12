#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${HERE}/../../../generated/native"
mkdir -p "$OUT"
gcc -O2 -fPIE -pie -o "${OUT}/pie_binary" "${HERE}/pie_binary.c"
file "${OUT}/pie_binary" || true
