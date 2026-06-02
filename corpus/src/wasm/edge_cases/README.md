# WebAssembly edge-case playground

WAT (WebAssembly text) sources exercising the proposal frontier (GC, memory64, multi-memory, threads, SIMD128, EH, tail calls, component model, branch hints). They feed `disrobe-pass-wasm-deob`.

## Coverage

| file | category | proposal | what it exercises |
|------|----------|----------|-------------------|
| `br_table_large.wat` | control | core | `br_table` with 64+ targets stresses table decoding. |
| `memory64.wat` | memory | memory64 | i64-indexed memory + load/store/size. |
| `multi_memory.wat` | memory | multi-memory | two memories with cross-memory `memory.copy`. |
| `gc_types.wat` | types | gc | `struct`, `array`, `i31ref` plus `ref.i31`/`i31.get_s`. |
| `tail_calls.wat` | call | tail-call | `return_call` + `return_call_indirect` (proper tail recursion). |
| `threads_atomics.wat` | concurrent | threads | shared memory, `atomic.rmw.*`, `memory.atomic.wait32/notify`. |
| `simd128.wat` | simd | simd128 + relaxed-simd | `i32x4`/`f32x4` lane ops, `shuffle`, `v128.load32_lane`, `relaxed_madd`. |
| `eh_try_table.wat` | eh | exception-handling | `tag` declarations + `try_table` + `throw` + `catch_all`. |
| `reference_types.wat` | ref | reference-types | `externref` table + `funcref` `call_indirect`. |
| `table_ops.wat` | table | reference-types | `table.grow`/`fill`/`copy`/`size` over `funcref` table. |
| `bulk_memory.wat` | memory | bulk-memory | `memory.init` (active + passive) + `memory.copy`/`fill` + `data.drop`. |
| `segments_modes.wat` | segments | reference-types | active / passive / declared elem segments + `table.init` + `data.drop`/`elem.drop`. |
| `component_preamble.wat` | component | component-model | `(component ...)` with embedded `(core module ...)` + `canon lift`. |
| `component_adapter.wat` | component | component-model | host import + `canon lower` adapter funcs + memory wiring. |
| `dwarf_custom_section.wat` | debug | custom-sections | `@custom` blocks for `name`, `external_debug_info`, `.debug_info`, `.debug_line`. |
| `branch_hints.wat` | metadata | branch-hinting | `@metadata.code.branch_hint` annotation on `br_if`. |

## Validation

`wat2wasm` is not on PATH in this workspace; these are best-effort syntactic WAT fixtures. To validate locally:

```powershell
foreach ($f in Get-ChildItem *.wat) {
    wat2wasm --enable-all $f --output ($f.BaseName + '.wasm')
}
```

The `--enable-all` flag is required because most fixtures sit on the proposal frontier (GC, memory64, multi-memory, tail-call, threads, EH, components, branch-hinting).
