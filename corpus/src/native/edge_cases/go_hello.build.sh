#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${HERE}/../../../generated/native"
mkdir -p "$OUT"
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "${OUT}/go_hello" "${HERE}/go_hello.go"
file "${OUT}/go_hello" || true
