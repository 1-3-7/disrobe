#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="$here/dwarf_hello.wasm"
if ! command -v clang >/dev/null 2>&1; then
  echo "clang not on PATH; skipping dwarf_hello.wasm generation" >&2
  exit 0
fi
clang --target=wasm32 -g -O0 -nostdlib -Wl,--no-entry -Wl,--export-all \
  -o "$out" "$here/dwarf_hello.c"
echo "wrote $out"
