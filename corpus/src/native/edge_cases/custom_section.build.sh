#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${HERE}/../../../generated/native"
mkdir -p "$OUT"
gcc -O2 -o "${OUT}/custom_section" "${HERE}/custom_section.c"
file "${OUT}/custom_section" || true
