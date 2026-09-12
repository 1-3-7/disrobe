#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${HERE}/../../../generated/native"
mkdir -p "$OUT"
gcc -O2 -fvisibility=hidden -o "${OUT}/hidden_visibility" "${HERE}/hidden_visibility.c"
file "${OUT}/hidden_visibility" || true
