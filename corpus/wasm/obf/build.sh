#!/usr/bin/env bash
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
src="$here/src"
real="$here/real"
mkdir -p "$real"

if command -v emcc >/dev/null 2>&1; then
  cc=(emcc)
  cc_kind="emcc"
elif [ -n "${CLANG:-}" ] && [ -x "$CLANG" ]; then
  cc=("$CLANG")
  cc_kind="clang"
elif command -v clang >/dev/null 2>&1; then
  cc=(clang)
  cc_kind="clang"
else
  echo "no wasm C compiler found: install emscripten (emcc) or LLVM (clang with the wasm32 target)" >&2
  exit 1
fi

if ! command -v wasm-tools >/dev/null 2>&1; then
  echo "wasm-tools not found: cargo install wasm-tools" >&2
  exit 1
fi

compile() {
  local out="$1" optflag="$2" src_file="$3"
  shift 3
  if [ "$cc_kind" = "emcc" ]; then
    "${cc[@]}" "$optflag" -s STANDALONE_WASM=1 -s PURE_WASI=0 --no-entry "$@" \
      -o "$out" "$src_file"
  else
    "${cc[@]}" --target=wasm32 "$optflag" -nostdlib -Wl,--no-entry -Wl,--strip-all "$@" \
      -o "$out" "$src_file"
  fi
}

emit_wat() {
  local wasm="$1" wat="$2"
  wasm-tools validate "$wasm"
  wasm-tools print "$wasm" >"$wat"
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
  -Wl,--export=classify
compile "$real/cff_cond_diamond.clean.wasm" -O2 "$src/cff_cond_diamond.clean.c" \
  -Wl,--export=classify

compile "$real/cff_cond_loop.obf.wasm" -O0 "$src/cff_cond_loop.c" \
  -Wl,--export=accumulate
compile "$real/cff_cond_loop.clean.wasm" -O2 "$src/cff_cond_loop.clean.c" \
  -Wl,--export=accumulate

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

if command -v rustc >/dev/null 2>&1 \
  && rustc --print target-list 2>/dev/null | grep -qx wasm32-unknown-unknown; then
  rustc --target wasm32-unknown-unknown -O --crate-type cdylib -C panic=abort \
    -o "$real/wasmixer_ondemand.obf.wasm" "$src/wasmixer_ondemand.rs"
else
  echo "rustc with wasm32-unknown-unknown not found: skipping wasmixer_ondemand fixture" >&2
fi

for f in "$real"/*.wasm; do
  base="${f%.wasm}"
  emit_wat "$f" "$base.wat"
done

echo "built real wasm + wat under $real (compiler: $cc_kind)"
