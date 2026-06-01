#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT="$REPO_ROOT/corpus/wasm"
WAT_DIR="$OUT/wat"

DRY_RUN=0
if [ "${1:-}" = "--dry-run" ]; then DRY_RUN=1; fi

if [ "$DRY_RUN" = "1" ]; then
    echo "[plan] mkdir -p $WAT_DIR"
else
    mkdir -p "$WAT_DIR"
fi

write_wat() {
    local name="$1"; local body="$2"
    local wat_path="$WAT_DIR/$name"
    local wasm_path="${wat_path%.wat}.wasm"
    if [ "$DRY_RUN" = "1" ]; then
        echo "[plan] write $wat_path"
        echo "[plan] wasm-tools parse $wat_path -> $wasm_path"
        return
    fi
    printf '%s\n' "$body" > "$wat_path"
    if wasm-tools parse "$wat_path" -o "$wasm_path" >/dev/null 2>&1 && [ -f "$wasm_path" ]; then
        echo "[ok]   baked $wasm_path"
    else
        echo "[skip] wasm-tools missing or fixture $name unsupported by installed toolchain"
    fi
}

write_wat 'stack_switching.wat' '(module
  (type $ft (func))
  (type $ct (cont $ft))
  (tag $t)
  (func $worker
    (suspend $t)
    (return))
  (func (export "main")
    (cont.new $ct (ref.func $worker))
    (resume $ct (on $t 0))
    (return)))'

write_wat 'gc_extern_convert.wat' '(module
  (func (export "round_trip") (param externref) (result externref)
    local.get 0
    any.convert_extern
    extern.convert_any))'

write_wat 'function_refs.wat' '(module
  (type $ft (func (param i32) (result i32)))
  (func $square (param i32) (result i32)
    local.get 0
    local.get 0
    i32.mul)
  (func (export "go") (param i32) (result i32)
    local.get 0
    ref.func $square
    call_ref $ft))'

write_wat 'js_string_builtins.wat' '(module
  (type $ft0 (func (param i32) (result (ref extern))))
  (type $ft1 (func (param (ref extern) (ref extern)) (result (ref extern))))
  (import "wasm:js-string" "fromCharCode" (func (type $ft0)))
  (import "wasm:js-string" "concat" (func (type $ft1))))'

write_wat 'custom_page_size.wat' '(module (memory 1 (pagesize 1)))'
