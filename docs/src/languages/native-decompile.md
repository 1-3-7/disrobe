# Native decompile (x86-64 / AArch64 to C or Rust)

`disrobe`'s own x86-64 and AArch64 decompiler lifts native machine code to C or idiomatic Rust with no external tool and no install step, and can drive Ghidra headlessly instead when you want its whole-program recovery.

For symbol recovery, disassembly, and identification see the [native guide](./native.md); for packers and VM protectors see [native unpacking](./native-unpack.md).

## At a glance

| Surface | Support |
|---|---|
| Architectures | x86-64 and AArch64, both lifting to full pseudo-code through the same shared IR |
| Output formats | C (default) or idiomatic Rust |
| Call resolution | Whole-program: each callee's real name and integer arity resolved against the sibling function set, then the caller re-recovered with that call graph stitched in |
| Switch dispatch | Dense switch recovered from the binary's own jump table |
| Type recovery | Structs from fixed-offset access (`p->field_8`), arrays from scaled indexing (`a[i]`), unions from conflicting widths, integer width and signedness per frame slot |
| API types | Resolved imports propagated backward into caller locals from a curated libc, kernel32, and ws2_32 prototype database, each tagged with `library!function` provenance |
| Calling convention | Inferred per function, including x86 `thiscall` and `vectorcall` |
| Vectorized loops | SSE/AVX reduction and pointer-walk map kernels lowered back to the equivalent scalar loop |
| AArch64 devirtualizer | Symbolic, on by default in a full build, `--no-devirt` to disable; transactional, reverts on any proof miss |
| Grading | Execution-differential recompilation against real gcc, clang, or rustc, never against disrobe's own prior output |
| Sidecars | `manifest.json` (schema `disrobe.native.decompile/v1`) and `types.json` (schema `disrobe.native.types/v1`) |
| Optional backend | Ghidra headless via `--backend ghidra` |

## Commands

```sh
disrobe native decompile app.exe --out decompiled/                 # x86-64 -> C, default backend
disrobe native decompile app.exe --format rust --out decompiled/   # x86-64 -> idiomatic Rust
disrobe native decompile app_arm64 --out decompiled/               # aarch64 -> pseudo-C, symbolic devirt on by default
disrobe native decompile app_arm64 --no-devirt --out decompiled/   # aarch64 without the symbolic devirtualizer
disrobe native decompile app.exe --backend ghidra --out decompiled/
```

Output lands at `<out>/<stem>.c` or `<out>/<stem>.rs` alongside a `manifest.json` (schema `disrobe.native.decompile/v1`) listing which functions recovered, which did not and why, and the emitted symbol name for each, plus the `types.json` sidecar.

## Coverage and fidelity

### Call resolution and structure

`--backend native` (the default) is disrobe's own x86-64 and AArch64 decompiler: no external tool, no install step. It performs whole-program call resolution over every function the module discovers, not isolated per-function guessing. Each function is leaf-recovered in the object's context, its outgoing calls are walked to resolve each callee's real name and integer arity against the sibling function set (falling back to the object's own relocations when a call target is a link-time placeholder in an unlinked object), then the caller is re-recovered with that call graph stitched in. Dense switch dispatch is recovered from the binary's own jump table rather than guessed. A function with no outgoing calls degrades to a plain leaf recovery, so stitching only ever improves recovery, never regresses it. AArch64 function bodies lift to full pseudo-code through the same shared IR, not disassembly alone.

### Type recovery

Types are inferred from the access shape rather than left as raw registers. A pointer walked at several fixed offsets recovers as a struct with named fields (`p->field_8`), a base indexed by a scaled register recovers as an array (`a[i]`), and offsets read at conflicting widths recover as a union. The calling convention is inferred per function, including x86 `thiscall` (implicit `this` in `ecx`) and `vectorcall` (SSE/AVX register arguments), so the recovered signature matches how the function is actually called.

Alongside the source, `native decompile` writes a `types.json` sidecar (schema `disrobe.native.types/v1`) recording the recovered integer width and signedness of each frame slot. The `disrobe-typerec` crate reads those signals straight from instruction semantics, subregister access, `movsx`/`movzx`, `div`/`idiv`, `sar`/`shr`, and signed against unsigned compares, and resolves them over a lattice with union-find. A frame slot the compiler reused for two variables is split back into distinct objects by a region-typed memory-SSA and live-range pass, so a reused slot recovers as two types instead of one blurred type that loses the signedness of both, and the same crate grades the struct, array, and union shapes the decompiler recovers from those access paths.

When a recovered call reaches a known library or OS function, resolved through the PE import table or ELF relocations to a curated libc, kernel32, and ws2_32 prototype database, that function's parameter and return types are propagated backward into the caller's locals through the same region memory-SSA and written into `types.json` as `api_slots`, each carrying its `library!function` provenance so an API-derived type is distinguishable from an inferred one; an unresolved import, an ordinal-only import, or a call whose backpropagated type conflicts abstains rather than guessing, and those API-derived caller-local types are graded on a stripped-versus-unstripped clang corpus against the unstripped DWARF, recovering pointer, integer-width, and sign with zero wrong types.

Graded against an unstripped sibling's DWARF on an `-O0` corpus, integer width and struct field offset and per-field width recover at recall 1.0, live-range splitting lifts signedness recall from 0.25 to 1.0 on the slot-reuse cases, and mutation checks confirm the grader rejects seeded-wrong widths, signs, field offsets, and merged or invented fields instead of passing everything.

### AArch64 symbolic devirtualizer

On the AArch64 path a symbolic devirtualizer runs before structuring, on by default in a full build and disabled with `--no-devirt`. It folds conditional arms it can prove dead against the path constraints, then hands the simplified function to the structurer. The fold is transactional: on any proof miss or budget exhaustion it reverts to the original function, so it can only ever replace a construct with a proven-equivalent one and never invents an edge. Per-function fold counts and status land in the decompile `manifest.json` under `devirt`.

### Auto-vectorized loops

Auto-vectorized loops are recovered to their scalar meaning: the C backend recognizes SSE/AVX reduction and pointer-walk map kernels that gcc and clang emit at `-O2`/`-O3` and lowers them back to the equivalent scalar loop, tracing each argument to its pristine ABI register so a compiler's entry-sequence register swap does not misattribute the length to the output pointer. Reassociation-unsafe floating-point vector loops are rejected rather than lowered to a wrong scalar form.

### Grading

Every recovered function is graded by execution-differential recompilation against real gcc, clang, or rustc, never against disrobe's own prior output. The AArch64 lift is held to the same bar against real `clang -O2` machine code, and the struct, array, and union recovery is asserted on recompiled-and-executed fixtures rather than by inspection. The vectorized-loop recovery is held to the same bar: the recovered scalar loop is recompiled and its output compared bit-for-bit against the original compiled kernel across a spread of input lengths, and on Linux at least one gcc `-O3` pointer-walk reduction must recover and execute-prove (`simd_devirt_oracle.rs`).

### Ghidra backend

`--backend ghidra` runs Ghidra headlessly (install it with `disrobe install-deps ghidra`) and returns pseudo-C alongside the standardized emits.

## Limits

- AArch64 function discovery is symbol-table-based today (the linear-sweep function finder is x86-only), so a stripped AArch64 binary surfaces fewer functions than its unstripped sibling, which enumerates and decompiles in full.
- On the AArch64 path, control-flow-flattening deflatten and jump-table edge rewrite are noted as deferred in the `devirt` manifest section.
- Where the byte stream carries no sign signal for a frame slot, the `types.json` sidecar reports it as unknown rather than guessing.
- An unresolved import, an ordinal-only import, or a call whose backpropagated type conflicts abstains rather than guessing an API-derived type.
- Reassociation-unsafe floating-point vector loops are rejected rather than lowered to a wrong scalar form.
- Reach for `--backend ghidra` on large, deeply nested binaries where Ghidra's whole-program type and structure recovery still leads: `disrobe`'s job there is to hand it a clean, unpacked, symbol-rich input.
