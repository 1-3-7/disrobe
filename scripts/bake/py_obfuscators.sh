#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT_DIR="${1:-$REPO_ROOT/corpus/python/obfuscators}"

mkdir -p "$OUT_DIR"
echo "[bake] repo=$REPO_ROOT out=$OUT_DIR"

cd "$REPO_ROOT"
cargo run --quiet --example bake_obfuscators -- "$OUT_DIR"

count=$(find "$OUT_DIR" -type f | wc -l)
bytes=$(find "$OUT_DIR" -type f -printf '%s\n' | awk '{s+=$1} END {print s}')
echo "[bake] fixtures=$count bytes=$bytes"
