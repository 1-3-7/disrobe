#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
src="$here/src"
real="$here/real"
mkdir -p "$real"

clang="${CLANG:-clang}"
wasm_tools="${WASM_TOOLS:-wasm-tools}"
rustc="${RUSTC:-rustc}"

require_version() {
  local tool="$1" expected="$2"
  local actual
  if ! actual="$("$tool" --version 2>/dev/null | head -n 1)"; then
    echo "$tool not found: records.toml pins $expected" >&2
    exit 1
  fi
  case "$actual" in
    *"$expected"*) ;;
    *)
      echo "$tool reports '$actual', but records.toml pins $expected" >&2
      exit 1
      ;;
  esac
}

require_version "$clang" "clang version 22.1.6"
require_version "$wasm_tools" "wasm-tools 1.250.0"
require_version "$rustc" "rustc 1.95.0"

compile() {
  local out="$1" optflag="$2" src_file="$3"
  shift 3
  "$clang" --target=wasm32 "$optflag" -nostdlib -Wl,--no-entry -Wl,--strip-all "$@" \
    -o "$out" "$src_file"
}

emit_wat() {
  local wasm="$1" wat="$2"
  "$wasm_tools" validate "$wasm"
  "$wasm_tools" print "$wasm" >"$wat"
}

compile "$real/mba_checksum.obf.wasm" -O2 "$src/mba_checksum.c" \
  -Wl,--export=mix -Wl,--export=checksum -Wl,--export=blend
compile "$real/mba_checksum.clean.wasm" -O2 "$src/mba_checksum.clean.c" \
  -Wl,--export=mix -Wl,--export=checksum -Wl,--export=blend

compile "$real/callind_dispatch.obf.wasm" -O0 "$src/callind_dispatch.c" \
  -Wl,--export=run
compile "$real/callind_dispatch.clean.wasm" -O0 "$src/callind_dispatch.clean.c" \
  -Wl,--export=run

compile "$real/cff_pipeline.obf.wasm" -O2 "$src/cff_pipeline.c" \
  -Wl,--export=pipeline
compile "$real/cff_pipeline.clean.wasm" -O2 "$src/cff_pipeline.clean.c" \
  -Wl,--export=pipeline

compile "$real/cff_cond_diamond.obf.wasm" -O0 "$src/cff_cond_diamond.c" \
  -Wl,--no-stack-first -Wl,--export=classify
compile "$real/cff_cond_diamond.clean.wasm" -O2 "$src/cff_cond_diamond.clean.c" \
  -Wl,--no-stack-first -Wl,--export=classify

compile "$real/cff_cond_loop.obf.wasm" -O0 "$src/cff_cond_loop.c" \
  -Wl,--no-stack-first -Wl,--export=accumulate
compile "$real/cff_cond_loop.clean.wasm" -O2 "$src/cff_cond_loop.clean.c" \
  -Wl,--no-stack-first -Wl,--export=accumulate

compile "$real/opaque_select.obf.wasm" -O0 "$src/opaque_select.c" \
  -Wl,--export=pick -Wl,--export=scale
compile "$real/opaque_select.clean.wasm" -O2 "$src/opaque_select.clean.c" \
  -Wl,--export=pick -Wl,--export=scale

compile "$real/trunc_sat.obf.wasm" -O0 "$src/trunc_sat.c" \
  -Wl,--export=i32_from_f32_s -Wl,--export=i32_from_f32_u \
  -Wl,--export=i32_from_f64_s -Wl,--export=i32_from_f64_u \
  -Wl,--export=i64_from_f32_s -Wl,--export=i64_from_f32_u \
  -Wl,--export=i64_from_f64_s -Wl,--export=i64_from_f64_u \
  -Wl,--export=mixed

compile "$real/decrypt_stub.obf.wasm" -O0 "$src/decrypt_stub.c" \
  -Wl,--export=plaintext_ptr

# wasm-ld writes the output file name into the module name, so rustc links under the recorded name.
"$rustc" --target wasm32-unknown-unknown -O --crate-type cdylib -C panic=abort \
  -o "$real/wasmixer_ondemand.wasm" "$src/wasmixer_ondemand.rs"
mv "$real/wasmixer_ondemand.wasm" "$real/wasmixer_ondemand.obf.wasm"

for f in "$real"/*.wasm; do
  base="${f%.wasm}"
  emit_wat "$f" "$base.wat"
done

echo "built real wasm + wat under $real; compare each .wat with its sha256 in records.toml"
