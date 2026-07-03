# WASM obfuscation recovery corpus

Benign, self-authored WebAssembly used to grade `disrobe-pass-wasm-deob`'s
`recover_module` against a wasmtime execution differential. Every `.obf.wat`
under `real/` is the output of a **real compiler toolchain** applied to the
benign C source in `src/`; the matching `.clean.wat` is the same program written
without the obfuscation, also compiled by the real toolchain. The oracle is
wasmtime execution of the clean original; the recovered module must produce
identical exported-function outputs over the input battery in
`tests/recover_differential.rs`.

No malware. No third-party binaries. Every C source in `src/` is hand-authored.

## How produced (real toolchain)

- C to wasm: `clang` 22.1.6 (LLVM `fc4aad7b5db3`) targeting `wasm32` with
  `wasm-ld`. This is the same LLVM wasm backend Emscripten drives; these kernels
  are pure computation, so the emscripten libc/JS shim is not needed and is
  omitted. `build.sh` prefers `emcc` if it is on `PATH` and otherwise falls back
  to `clang --target=wasm32` (identical backend).
- text emission + validation: `wasm-tools` 1.250.0 (`wasm-tools validate`,
  `wasm-tools print`).
- `wasmixer_ondemand` is the one Rust source (`src/wasmixer_ondemand.rs`), built by
  `rustc` 1.95.0 targeting `wasm32-unknown-unknown` at `-O`. It models WASMixer's
  on-demand string decryption (arXiv 2308.03123): an encrypted literal sits in an
  active data segment and a `dec_load(off, len)` thunk XOR-walks it in place at
  use time. The rustc LLVM backend is a real production wasm toolchain; this is
  the same wat-at-test-time convention as the clang fixtures.

Run `corpus/wasm/obf/build.sh` (optionally with `CLANG=/path/to/clang.exe`) to
regenerate. It writes the real `.wasm` binaries and their `.wat` disassembly to
`real/`. The `.wasm` blobs are git-ignored (`corpus/**/*.wasm`); the committed,
reviewable artifact is the real-toolchain `.wat` (the compiler's bytes printed
by `wasm-tools print`), which the differential assembles with the `wat` crate at
test time. This matches the rest of the repo's wat-at-test-time convention.

### Exact per-sample commands

```
clang --target=wasm32 -O2 -nostdlib -Wl,--no-entry -Wl,--strip-all \
  -Wl,--export=mix -Wl,--export=checksum -Wl,--export=blend \
  -o real/mba_checksum.obf.wasm src/mba_checksum.c
clang --target=wasm32 -O0 -nostdlib -Wl,--no-entry -Wl,--strip-all \
  -Wl,--export=run -o real/callind_dispatch.obf.wasm src/callind_dispatch.c
clang --target=wasm32 -O2 -nostdlib -Wl,--no-entry -Wl,--strip-all \
  -Wl,--export=pipeline -o real/cff_pipeline.obf.wasm src/cff_pipeline.c
clang --target=wasm32 -O0 -nostdlib -Wl,--no-entry -Wl,--strip-all \
  -Wl,--export=pick -Wl,--export=scale -o real/opaque_select.obf.wasm src/opaque_select.c
clang --target=wasm32 -O0 -nostdlib -Wl,--no-entry -Wl,--strip-all \
  -Wl,--export=plaintext_ptr -o real/decrypt_stub.obf.wasm src/decrypt_stub.c
```

## Pairs, real-tool transform, and recovery

| pair | obfuscation in the real wasm | how it got there | recovery |
|------|------------------------------|------------------|----------|
| `mba_checksum` | `a + b` is written in C as the XOR-carry identity `(a ^ b) + 2*(a & b)`; LLVM at `-O2` lowers `2*(a&b)` to `(a&b) << 1` and keeps the identity (it does not fold it back to `a + b`). `mix` and `blend` carry one tee-free MBA add each | real clang `-O2` | MBA folding: the lifter reads `e << k` as `e * 2^k`, proves value-equivalence over the bitvector domain via `disrobe-mba`, and re-emits the minimal `a + b`. Two expressions fold |
| `callind_dispatch` | a C function-pointer table; at `-O0` each call is `i32.const A; i32.load offset=O` (the slot index is read from the `table[]` data segment) then `call_indirect` | real clang `-O0` | call_indirect resolution: read the 4 LE bytes the data segment stores at `A+O`, map that table slot through the active element segment to the concrete callee, rewrite to a direct `call`. Three calls resolve |
| `cff_pipeline` | a C `for(;;) switch(state)` state machine; LLVM at `-O2` lowers it to a `br_table` dispatcher (`loop` wrapped in an outer `block`, the relooper block-stack idiom) and does not reloop it | real clang `-O2` | control-flow unflattening: recover the dispatcher loop (even when nested one block deep), the per-state case bodies and their next-state edges, then re-linearize when the recovered successor relation is a single path to the loop exit |
| `cff_cond_diamond` | a C `while(1) switch(state)` machine whose state transition is data-dependent (`if (n > 10) state = 1; else state = 2;`); at `-O0` LLVM keeps a memory-slot `br_table` dispatcher and lowers the branch to a nested `block/block/br_if` that stores two different next states | real clang `-O0` | conditional unflattening: recover the state-transition graph with conditional successors, then reloop the diamond into a real `if/else` over the recovered guard, dropping the state variable and dispatcher entirely |
| `cff_cond_loop` | a C `while(1) switch(state)` machine with a loop back edge and a data-dependent branch inside the body (`for` loop guard plus `if ((i & 1) == 0)`); `-O0` keeps a memory-slot `br_table` dispatcher with a back edge | real clang `-O0` | conditional unflattening: reloop the state graph into a `loop` with a nested `if/else`, using dominators to place the back edge as a `continue` and the single loop exit as the fall-through |
| `decrypt_stub` | a C loop XORs a `static` buffer in place with the constant key `0x4b`; at `-O0` LLVM keeps the `i32.load8_u; i32.const 75; i32.xor; i32.store8` loop and emits the ciphertext as a real data segment | real clang `-O0` | pure decrypt-stub extraction: detect the constant-key byte loop in a call-free function and apply it to the static data section so the plaintext `helloworld` is visible. Unit-checked, not execution-graded |
| `wasmixer_ondemand` | a Rust source whose encrypted literal lives in an active data segment and whose `dec_load(off, len)` thunk XOR-walks it in place; `-O` unrolls the loop 4x and bakes the segment base into the body as `i32.const 1048576` | real `rustc` `-O` (wasm32) | sandbox on-demand unwrap: statically resolve the data segment `(base, len)`, detect that the thunk embeds the base (so it takes a relative offset), invoke it under a fuel + epoch-bounded wasmtime sandbox with `(0, len)`, and read the decrypted bytes back at the returned pointer. Execution-graded: the recovered bytes must equal the known input `disrobe/wasm/on-demand-decrypt` |

## Honest scope (real-tool output vs walled)

Recovered end to end from **real clang output** and graded by the differential:

- MBA add encodings emitted by `-O2` as `(a&b) << 1 + (a^b)` (and the general
  `e << k` to `e * 2^k` rewrite), proven by `disrobe-mba`.
- `call_indirect` whose index is loaded at `-O0` from a constant address in an
  active data segment, mapped through a statically-known element segment.
- control-flow flattening whose `-O2` `br_table` state graph is a single linear
  chain to the loop exit, including the `loop`-inside-`block` nesting LLVM emits.
- control-flow flattening whose state transitions are data-dependent: the
  relooper recovers the transition graph (conditional successors included) and
  rebuilds `if/else` and `loop` structure over a real `-O0` `br_table` dispatcher,
  graded by wasmtime equivalence to the clean original in
  `tests/cff_conditional_reloop.rs`. Genuinely irreducible transition graphs (for
  example a loop with two distinct exits) stay reported, not faked.
- constant-key byte decrypt loops a real `-O0` build leaves intact.

Walled, with the physical reason:

- `opaque_select.obf.wat` is **real clang `-O0`** and is intentionally NOT
  folded. Two findings drive this: (1) any opaque predicate LLVM can prove
  constant it removes itself at `-O1`+ (verified: `9 % 3 == 0` and
  `collatz(27) == 1` both become straight-line code), so there is no artifact
  left to fold; (2) at `-O0` the predicate survives only as a block-based
  `br_if` guarded by a `call` to a stack-frame-using helper (`collatz_steps`),
  and proving it constant needs an interprocedural wasm interpreter over the
  called function's linear-memory locals, which is out of scope for this pass.
  The differential asserts recover_module reports zero opaque folds here yet
  leaves `pick`/`scale` behaviorally identical to the clean oracle. The
  structured-`if`/`else` constant and Collatz opaque folder is still real and is
  exercised by `recover::tests::folds_constant_and_collatz_opaque_predicates_when_present`
  and the `recover::opaque` unit tests; no practically-installable tool emits a
  foldable opaque predicate on wasm, so that logic is graded on the shape a
  structured producer (or a structured-if obfuscator) emits rather than on
  clang `-O0` output.
- `checksum` in `mba_checksum` does not fold: at `-O2` LLVM shares the common
  subexpression `k = i+3` through a `local.tee` mid-expression, and folding
  across a side-effecting tee is unsound without dataflow, so the straight-line
  lifter leaves it. The differential still proves it behaviorally equivalent.
- control-flow flattening whose recovered state graph branches (a state with two
  successors) is not re-linearized; the deobfuscator reports it walled rather
  than emit an unproven restructuring.
- decrypt stubs whose key is derived at runtime (not a constant in the artifact)
  are walled: the plaintext is not recoverable from static bytes alone.

## Named-obfuscator family pairs (spec-faithful synthetic)

WasmMixer, Wobfuscator, and Jscrambler are JavaScript/build-tool pipelines, not
on-box C/Rust compilers, so their three pairs are **hand-authored spec-faithful
synthetic** rather than real-toolchain output. Each `.obf.wat` reproduces the
exact structural transform the named tool emits, paired with the hand-written
`.clean.wat` original. The oracle is the same wasmtime execution differential:
the recovered module must produce identical exported outputs to the clean
original over the input battery, and must re-validate and be import-free. Graded
by `named_obfuscator_families_recover_to_clean_behavior_under_wasmtime` and
`named_family_recovery_is_idempotent_and_import_free`.

| pair | transform reproduced | recovery |
|------|----------------------|----------|
| `wasmixer_inflate` | WasmMixer splits a function body into table-dispatched fragments and routes each through `call_indirect` with a constant slot index, inflating the function/element count (arXiv 2308.03123) | de-virtualize the dispatch: map each constant table slot through the active element segment to its concrete fragment and rewrite to a direct `call`, then prune the now-dead element segment. Three fragments de-virtualized, the dispatch table pruned, behavior identical to the single-function clean original |
| `wobfuscator_import` | Wobfuscator hoists native operations out to the JS host as `env` imports (`op_xor`, `op_and`, ...) and replaces the native opcode with a `call` to the import, so the wasm cannot run without the JS shim | re-inline each imported binary op back to its native wasm opcode by import name + i32-binary signature, then drop the now-dead imports. Two ops re-inlined, both imports dropped, the recovered module is import-free and behaves identically to the native-opcode clean original |
| `jscrambler_guard` | Jscrambler injects an integrity-check import (module `jsc`, name `__jscrambler_integrity`) called for its side effect plus an opaque always-false `br_if` guard around the real body | strip the integrity import (replacing the call with a behavior-preserving local stub) so the module runs without the JS guard host; the opaque guard is dead (always-false) and leaves behavior intact. Integrity import stripped, behavior identical to the clean original |

These are labeled synthetic precisely because no free, installable build of the
three tools exists on the box; the transform shapes are taken from each tool's
published output, and the recovery is graded against a real execution engine
(wasmtime), not against disrobe's own output.
