#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${HERE}/../../../generated/native"
mkdir -p "$OUT"
g++ -O2 -std=c++17 -o "${OUT}/cxx_virtual" "${HERE}/cxx_virtual_inheritance.cpp"
file "${OUT}/cxx_virtual" || true
