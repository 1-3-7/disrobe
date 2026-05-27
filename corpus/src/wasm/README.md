# WASM playground

Hand-authored `.wat` (WebAssembly text) sources compile to `.wasm` via `wat2wasm` (from [wabt](https://github.com/WebAssembly/wabt)) and feed `disrobe-pass-wasm-deob` (decompile, defrag, EH lift, opcode-table recovery).

| file | target | how to feed disrobe |
|------|--------|---------------------|
| `sources/add.wat` | simple `(func add (i32 i32) -> i32)` with locals, baseline decompile target | `wat2wasm sources/add.wat -o add.wasm && disrobe wasm decompile add.wasm` |
| `sources/branching.wat` | nested `block` + `br_table` + counted `loop`, exercises control-flow lift | `wat2wasm sources/branching.wat -o branching.wasm && disrobe wasm decompile branching.wasm` |
| `sources/memory.wat` | exported `memory` + `i32.load`/`i32.store` + data segment, exercises memory-access lift | `wat2wasm sources/memory.wat -o memory.wasm && disrobe wasm decompile memory.wasm` |
| `sources/exceptions.wat` | modern exception-handling (`tag` + `throw` + `try_table` + `catch`), exercises EH lift | `wat2wasm --enable-exceptions sources/exceptions.wat -o exceptions.wasm && disrobe wasm decompile exceptions.wasm` |

`wat2wasm` lives in `wabt`; if absent the `corpus/generate.{sh,ps1}` walker skips WASM compilation and logs `skipped wasm: wat2wasm not found`.
