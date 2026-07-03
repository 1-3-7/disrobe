#!/usr/bin/env bash
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
cd "$root"
export CARGO_INCREMENTAL=0
cargo run -p xtask -- evidence "$@"
echo "evidence rendered into evidence/results/; read evidence/results/EVIDENCE.md"
