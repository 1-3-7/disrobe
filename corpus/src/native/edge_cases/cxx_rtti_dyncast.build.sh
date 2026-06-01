#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${HERE}/../../../generated/native"
mkdir -p "$OUT"
g++ -O2 -std=c++17 -frtti -o "${OUT}/cxx_rtti" "${HERE}/cxx_rtti_dyncast.cpp"
file "${OUT}/cxx_rtti" || true
