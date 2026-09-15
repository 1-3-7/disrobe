# Edge-case playground (meta index)

This directory is the cross-language hub for every edge-case fixture under `corpus/src/<lang>/edge_cases/`. Each per-language directory has its own per-fixture README; this file is the global index linking categories to the pass crate they exercise.

## Per-language counts

| language | fixtures | target | path |
|----------|---------:|-------:|------|
| python | 38 | 30 | `corpus/src/python/edge_cases/` |
| javascript | 32 | 30 | `corpus/src/javascript/edge_cases/` |
| typescript | 21 | 20 | `corpus/src/typescript/edge_cases/` |
| wasm | 16 | 15 | `corpus/src/wasm/edge_cases/` |
| native | 10 sources + 10 build recipes | 10 | `corpus/src/native/edge_cases/` |
| java | 11 | 10 | `corpus/src/java/edge_cases/` |
| lua | 11 | 10 | `corpus/src/lua/edge_cases/` |
| **total** | **139** sources | **125** | |

## Category x pass-crate matrix

| edge-case category | pass crate(s) | languages with coverage |
|--------------------|---------------|------------------------|
| unicode identifier smuggling (bidi, CVE-2021-42574) | py-disasm, py-deob | python |
| raw-string / raw-bytes / format-spec literals | py-disasm, js-deob | python, javascript |
| async generators / async-for / async-with | py-disasm, js-deob | python, javascript |
| pattern matching (`match`/`switch`) | py-disasm, js-deob | python, java |
| sealed hierarchies / discriminated unions | py-disasm, js-deob | typescript, java |
| decorators / annotations / metadata | py-disasm, js-deob | python, typescript, java |
| metaclass / `__init_subclass__` hooks | py-disasm | python |
| exception groups / `except*` / `try_table` | py-disasm, wasm-deob | python, wasm |
| BigInt / large-int arithmetic | py-disasm, js-deob | python, javascript |
| typed arrays / `SharedArrayBuffer` / atomics | js-deob | javascript |
| `Proxy` / `Reflect` / `eval` dynamic dispatch | js-deob | javascript |
| `with` / sloppy mode | js-deob | javascript |
| recursive / variadic / conditional types | js-deob (TS frontend) | typescript |
| template literal types / mapped types | js-deob (TS frontend) | typescript |
| `using` declarations / disposable resources | js-deob (TS frontend) | typescript, python |
| WASM control flow (`br_table` x64) | wasm-deob | wasm |
| WASM memory features (memory64, multi-memory, bulk) | wasm-deob | wasm |
| WASM GC (struct / array / i31ref) | wasm-deob | wasm |
| WASM SIMD128 + relaxed-SIMD | wasm-deob | wasm |
| WASM tail calls (`return_call`) | wasm-deob | wasm |
| WASM threads + atomics | wasm-deob | wasm |
| WASM reference types + tables | wasm-deob | wasm |
| WASM component model | wasm-deob | wasm |
| WASM DWARF custom sections | wasm-deob, binfmt | wasm |
| WASM branch-hint metadata | wasm-deob | wasm |
| stripped ELF / Mach-O / PE | binfmt | native |
| PE TLS callbacks + anti-debug | binfmt | native |
| PIE / hidden-visibility binaries | binfmt | native |
| C++ virtual inheritance / RTTI / `dynamic_cast` | binfmt | native |
| Go / Rust static binaries | binfmt | native |
| Java sealed / records / pattern switch / text block | (future jvm pass) | java |
| Lua coroutines / metatables / LuaJIT FFI + bit ops | (future lua pass) | lua |

## Pipeline hooks

`corpus/generate.sh --edge-cases` & `corpus/generate.ps1 -EdgeCases` drive ONLY the edge-case fixtures through their respective compilers when available; they skip cleanly with `[skip]` logs when a compiler is missing. `xtask bake-fixtures --edge-cases` wraps the same path from Rust.

The machine-readable index lives in `manifest.json` alongside this README & is consumed by `disrobe-validator` corpus walks plus any external CI smoke check.
