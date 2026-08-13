# Native decompile (x86-64 to C or Rust; AArch64 to pseudo-C)

`disrobe`'s own x86-64 decompiler lifts native machine code to C or idiomatic Rust, while its AArch64 decompiler emits pseudo-C. Neither requires an external tool or install step. Ghidra can run headlessly instead when you want its whole-program recovery.

For symbol recovery, disassembly, and identification see the [native guide](./native.md); for packers and VM protectors see [native unpacking](./native-unpack.md).

## At a glance

| Surface | Support |
|---|---|
| Architectures | x86-64 uses the shared IR pipeline and emits C or Rust; AArch64 uses object-context and NIR recovery to emit pseudo-C |
| Output formats | C (default) for x86-64 and AArch64; idiomatic Rust for x86-64 only |
| Call resolution | Whole-program for validated direct same-image calls in linked AArch64 ELF inputs whose sibling target resolves unambiguously; unresolved, indirect, external, and ambiguous calls abstain. Relocatable AArch64 objects fail before output. |
| Switch dispatch | Dense switch recovered from the binary's own jump table |
| Type recovery | x86-64 structs from fixed-offset access (`p->field_8`), arrays from scaled indexing (`a[i]`), unions from conflicting widths, integer width and signedness per frame slot |
| API types | x86-64 resolved imports propagated backward into caller locals from a curated libc, kernel32, and ws2_32 prototype database, each tagged with `library!function` provenance |
| Calling convention | x86-64 inferred per function, including `thiscall` and `vectorcall` |
| AArch64 scalar floating point | `h0` to `h31`, `s0` to `s31`, and `d0` to `d31`; IEEE binary16, binary32, and binary64 arithmetic, conversion, comparison, rounding, and loads or stores |
| Vectorized loops | x86-64 SSE/AVX reduction and pointer-walk map kernels lowered back to the equivalent scalar loop |
| Constant division | x86-64 magic-multiply division and modulo recovered as `/` and `%` in C output and as `wrapping_div` and `wrapping_rem` in Rust output; a divisor the range check cannot confirm keeps the multiply and shift |
| AArch64 devirtualizer | Symbolic, on by default in a full build, `--no-devirt` to disable; transactional, reverts on any proof miss |
| Grading | C output is execution-differentially recompiled with real gcc or clang; x86-64 Rust output with rustc |
| Sidecars | `manifest.json` (schema `disrobe.native.decompile/v1`) for both architectures; x86-64 also emits `types.json` (schema `disrobe.native.types/v1`) |
| Optional backend | Ghidra headless via `--backend ghidra` |

## Commands

```sh
disrobe native decompile app.exe --out decompiled/                 # x86-64 -> C, default backend
disrobe native decompile app.exe --format rust --out decompiled/   # x86-64 -> idiomatic Rust
disrobe native decompile app_arm64 --out decompiled/               # aarch64 -> pseudo-C, symbolic devirt on by default
disrobe native decompile app_arm64 --no-devirt --out decompiled/   # aarch64 without the symbolic devirtualizer
disrobe native decompile app.exe --backend ghidra --out decompiled/
```

Output lands at `<out>/<stem>.c` or `<out>/<stem>.rs` alongside a `manifest.json` (schema `disrobe.native.decompile/v1`) listing which functions recovered, which did not and why, and the emitted symbol name for each. x86-64 output also carries the `types.json` sidecar.

## Coverage and fidelity

### Call resolution and structure

`--backend native` (the default) is disrobe's own x86-64 and AArch64 decompiler: no external tool, no install step. It performs whole-program call resolution over every function the module discovers, not isolated per-function guessing. For linked AArch64 ELF inputs, a validated direct same-image call resolves its callee's real name and integer arity only when the sibling target is unambiguous. Indirect, external, malformed, unsupported, and ambiguous calls abstain. Relocatable AArch64 objects fail before output because section-qualified function identity is not yet carried through the CLI. Dense switch dispatch is recovered from the binary's own jump table rather than guessed. A function with no validated outgoing calls degrades to a plain leaf recovery, so stitching only ever improves recovery, never regresses it. AArch64 uses object-context recovery first, with the NIR lift and image-backed recovery available as narrower fallbacks.

### AArch64 scalar floating point

The AArch64 lifter recognizes all 32 scalar floating-point registers through their `h`, `s`, and `d` views. Half-precision values use IEEE binary16 bits in the shared register model. The C emitter uses `_Float16`; the internal Rust emitter uses `u16` at function boundaries because stable Rust does not provide an `f16` primitive, then converts those bits through bounded binary16 helpers. Arithmetic, fused multiply-add, minimum and maximum, square root, rounding, integer conversion, precision conversion, comparison, selection, base-register scalar loads, scalar stores, and image-backed `s` and `d` literal-pool loads use the declared operand width. Literal-pool recovery reads only the encoded width from a mapped image range and refuses missing or truncated data. The scalar path models the default IEEE floating-point environment. A function that reads or writes FPCR refuses recovery because its rounding, flush-to-zero, default-NaN, or alternative-half controls can change scalar results. Ambient FPCR state established outside the function cannot be inferred, so output that depends on an externally selected nondefault state is not claimed as bit-exact. `q` and `v` operands remain vector operations and do not enter the scalar path.

### x86-64 type recovery

Types are inferred from the access shape rather than left as raw registers. A pointer walked at several fixed offsets recovers as a struct with named fields (`p->field_8`), a base indexed by a scaled register recovers as an array (`a[i]`), and offsets read at conflicting widths recover as a union. The calling convention is inferred per function, including x86 `thiscall` (implicit `this` in `ecx`) and `vectorcall` (SSE/AVX register arguments), so the recovered signature matches how the function is actually called.

Alongside the source, `native decompile` writes a `types.json` sidecar (schema `disrobe.native.types/v1`) recording the recovered integer width and signedness of each frame slot. The `disrobe-typerec` crate reads those signals straight from instruction semantics, subregister access, `movsx`/`movzx`, `div`/`idiv`, `sar`/`shr`, and signed against unsigned compares, and resolves them over a lattice with union-find. A frame slot the compiler reused for two variables is split back into distinct objects by a region-typed memory-SSA and live-range pass, so a reused slot recovers as two types instead of one blurred type that loses the signedness of both, and the same crate grades the struct, array, and union shapes the decompiler recovers from those access paths.

When a recovered call reaches a known library or OS function, resolved through the PE import table or ELF relocations to a curated libc, kernel32, and ws2_32 prototype database, that function's parameter and return types are propagated backward into the caller's locals through the same region memory-SSA and written into `types.json` as `api_slots`, each carrying its `library!function` provenance so an API-derived type is distinguishable from an inferred one; an unresolved import, an ordinal-only import, or a call whose backpropagated type conflicts abstains rather than guessing, and those API-derived caller-local types are graded on a stripped-versus-unstripped clang corpus against the unstripped DWARF, recovering pointer, integer-width, and sign with zero wrong types.

Graded against an unstripped sibling's DWARF on an `-O0` corpus, integer width and struct field offset and per-field width recover at recall 1.0, live-range splitting lifts signedness recall from 0.25 to 1.0 on the slot-reuse cases, and mutation checks confirm the grader rejects seeded-wrong widths, signs, field offsets, and merged or invented fields instead of passing everything.

### AArch64 symbolic devirtualizer

On the AArch64 path a symbolic devirtualizer runs before structuring, on by default in a full build and disabled with `--no-devirt`. It folds conditional arms it can prove dead against the path constraints, then hands the simplified function to the structurer. The fold is transactional: on any proof miss or budget exhaustion it reverts to the original function, so it can only ever replace a construct with a proven-equivalent one and never invents an edge. Per-function fold counts and status land in the decompile `manifest.json` under `devirt`.

### Auto-vectorized loops

Auto-vectorized loops are recovered to their scalar meaning: the C backend recognizes SSE/AVX reduction and pointer-walk map kernels that gcc and clang emit at `-O2`/`-O3` and lowers them back to the equivalent scalar loop, tracing each argument to its pristine ABI register so a compiler's entry-sequence register swap does not misattribute the length to the output pointer. Reassociation-unsafe floating-point vector loops are rejected rather than lowered to a wrong scalar form.

### x86-64 constant division and modulo

A compiler replaces a division by a constant with a multiply by a magic number, a shift, and a sign correction. The x86-64 path recognizes that sequence and emits the division again. C output uses `/` and `%`. Rust output uses `wrapping_div` and `wrapping_rem`. The recognized forms are a magic multiply whose product fits a single register, a wide multiply through the one-operand `mul` or `imul`, the add-form that carries an implicit high bit, the pre-shift form used for an even divisor, and the signed corrections taken from the sign of the dividend, of the product, or of the quotient. A dividend narrower than 64 bits must be zero-extended into an unsigned form or sign-extended into a signed form. An extension that does not match the form refuses the rewrite.

The divisor is not read out of the magic number. A candidate divisor is accepted only when the multiply and shift reproduce the exact quotient for every dividend in range. A multiply-shift pair that computes a fixed-point scale fails that check and stays a multiply and shift, so a scale is never renamed as a division. A perturbed shift amount, a perturbed multiplier, and a 32-bit magic applied to a 64-bit dividend fail the same range check.

The modulo is recovered from the tail that follows the quotient. Inside a bounded window after the matched sequence, the recovery tracks copies, additions, subtractions, multiplication by a constant, left shifts, and `lea` with a scale, then emits `%` for the register that ends up holding `dividend - quotient * divisor`. When the quotient is still live after that tail, the division and the modulo both emit.

The rewrite replaces straight-line code only. A back edge that targets the first instruction of the matched sequence, or any address before it, refuses the rewrite. A division inside a loop therefore keeps its multiply-and-shift form whenever the loop jumps back to or above the start of the matched sequence. Any other control transfer that lands inside the sequence refuses it as well. A store or a read-modify-write inside the sequence refuses it. Every register the sequence writes, other than the quotient and the copies of the dividend that outlive it, must be dead afterward.

The one-operand `imul` lifts as a signed wide multiply, so a signed 64-by-64 high-half product emits as `__int128` in C and as `i128` with `wrapping_mul` in Rust instead of taking the unsigned form.

Set `DISROBE_DEBUG=native` to print the address and the recovered divisor of each rewritten sequence.

### Grading

C output is graded by execution-differential recompilation against real gcc or clang, and x86-64 Rust output against rustc, never against disrobe's own prior output. The AArch64 pseudo-C lift is held to the C bar against real `clang -O2` machine code, and the struct, array, and union recovery is asserted on recompiled-and-executed fixtures rather than by inspection. The vectorized-loop recovery is held to the same C bar: the recovered scalar loop is recompiled and its output compared bit-for-bit against the original compiled kernel across a spread of input lengths, and on Linux at least one gcc `-O3` pointer-walk reduction must recover and execute-prove (`simd_devirt_oracle.rs`).

Constant-division recovery is held to the same C bar. It is measured over divisors 1 through 1024 plus sampled values up to 4294967295, at `-O1`, `-O2`, and `-Os`, for 32-bit and 64-bit dividends, with whichever of gcc, clang, and cc is on `PATH`, and a recovered divisor that differs from the one in the source is a failure. Recovered functions are recompiled and executed against the compiled original over a fixed spread of inputs, and that execution grading covers the loop bodies and the signed 128-bit high-half products as well as the plain division and modulo cases. Whole-program recovery is graded on its own, so the rewrite is proven reachable through `recover_program` and not only through a single leaf function (`pseudo_c_const_division_oracle.rs`).

### Ghidra backend

`--backend ghidra` runs Ghidra headlessly (install it with `disrobe install-deps ghidra`) and returns pseudo-C alongside the standardized emits.

## Limits

- AArch64 function discovery is symbol-table-based today (the linear-sweep function finder is x86-only), so a stripped AArch64 binary surfaces fewer functions than its unstripped sibling, which enumerates and decompiles in full.
- On the AArch64 path, control-flow-flattening deflatten and jump-table edge rewrite are noted as deferred in the `devirt` manifest section.
- AArch64 Rust emission is unsupported. `--format rust` fails before native recovery writes output.
- On x86-64, where the byte stream carries no sign signal for a frame slot, the `types.json` sidecar reports it as unknown rather than guessing.
- An unresolved import, an ordinal-only import, or a call whose backpropagated type conflicts abstains rather than guessing an API-derived type.
- Reassociation-unsafe floating-point vector loops are rejected rather than lowered to a wrong scalar form.
- Constant-division recovery is x86-64 only. The AArch64 path does not rewrite a magic multiply back into a division.
- Constant-division recovery starts from a magic multiply, so a divisor the compiler lowered to a plain shift stays a shift in the output.
- A magic multiply-shift sequence whose divisor the range check cannot confirm, including a fixed-point scale, is left as a multiply and a shift rather than rewritten.
- A constant division is left alone when a back edge targets the first instruction of the matched sequence or an earlier address, when another control transfer lands inside the sequence, or when the sequence writes to memory.
- Reach for `--backend ghidra` on large, deeply nested binaries where Ghidra's whole-program type and structure recovery still leads: `disrobe`'s job there is to hand it a clean, unpacked, symbol-rich input.
