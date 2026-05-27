#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT="$REPO_ROOT/corpus/v8"
HELLO='process.stdout.write("hello " + (42 + 0));'

DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then DRY_RUN=1; fi

if [ "$DRY_RUN" = "1" ]; then
    echo "[plan] mkdir -p $OUT"
else
    mkdir -p "$OUT"
fi

for v in 18 20 22 24; do
    out_dir="$OUT/node-$v"
    hello_path="$out_dir/hello-$v.js"
    jsc_path="$out_dir/hello-$v.jsc"
    if [ "$DRY_RUN" = "1" ]; then
        echo "[plan] mkdir -p $out_dir"
        echo "[plan] write $hello_path"
        echo "[plan] npx -y -p node@$v -p bytenode bytenode --compile $hello_path"
        continue
    fi
    mkdir -p "$out_dir"
    printf '%s\n' "$HELLO" > "$hello_path"
    if NODE_NO_WARNINGS=1 npx -y -p "node@$v" -p bytenode bytenode --compile "$hello_path" >/dev/null 2>&1 && [ -f "$jsc_path" ]; then
        echo "[ok]   baked $jsc_path"
    else
        echo "[skip] node $v unavailable or bytenode failed"
    fi
done
