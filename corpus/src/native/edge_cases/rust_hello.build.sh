#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${HERE}/../../../generated/native"
mkdir -p "$OUT"
rustc -C opt-level=3 -C strip=symbols -C codegen-units=1 -o "${OUT}/rust_hello" "${HERE}/rust_hello.rs"
file "${OUT}/rust_hello" || true
