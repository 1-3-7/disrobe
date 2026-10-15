# WebAssembly

`disrobe` parses WebAssembly modules, lifts them to four target surfaces, reverses Wasm-specific obfuscators, and decodes the Component Model and GC type graphs.

## At a glance

| Layer | Coverage |
|---|---|
| Lift targets | Rust, TypeScript, WAT, or C pseudo-source, or a JSON summary |
| Instruction set | MVP plus the SIMD, atomics, bulk-memory, table/element, reference, and tail-call proposals |
| Name recovery | Not applied: DWARF and source-map helpers exist, but no command calls them yet |
| Op-coverage grade | Every operator in the function lowered, and the re-emitted WAT re-parsed by an independent parser |
| Execution grade | Return values, trap parity, and linear memory compared against the original under wasmtime |
| Obfuscators | Jscrambler-WASM integrity imports stripped; Wobfuscator imported operators re-inlined by import name, or from a static host operator table with `--host-script`; Wasmixer fragments inlined and decrypt-stub plaintext reported; Tigress-style `switch` dispatchers unflattened; wasm-name-obfuscator detected and classified only |
| Control-flow unflattening | Dispatcher loops whose state lives in a local, a private mutable global, or a non-atomic `i32` memory slot are rebuilt as structured control flow, including a stack-frame slot whose state writes must stay; a dispatcher outside that set is left in place |
| Envelopes | Component Model, memory64, and the GC type graph parsed by dedicated scanners; threads instructions also lift to C, Rust, and TypeScript |

## Commands

```sh
disrobe wasm decompile module.wasm --target rust --out lifted.rs
disrobe wasm decompile module.wasm --target ts   --out lifted.ts
disrobe wasm decompile module.wasm --target wat  --out lifted.wat
disrobe wasm decompile module.wasm --target c    --out lifted.c
disrobe wasm decompile module.wasm --target json --out summary.json
disrobe wasm deob module.wasm --out clean.wat --emit-wasm clean.wasm
disrobe wasm deob module.wasm --out clean.wat --host-script host.js   # Wobfuscator host operator table
disrobe wasm component module.wasm        # parse the Component Model envelope -> world / adapter manifest
disrobe wasm types module.wasm            # recover the GC type graph (struct / array / ref types)
```

`decompile` lifts to Rust, TypeScript, WAT, or C pseudo-source, or a JSON summary.

`deob` writes the recovered module as WAT to `--out`. Add `--emit-wasm` to write the recovered binary as well. Two JSON files land beside the WAT with its extension replaced, so `--out clean.wat` produces `clean.summary.json` and `clean.recovery.json`. The recovery report holds the per-transformation counts, including the unflattening counts described below, the decrypted Wasmixer literals and the host-table entries that were refused.

## Coverage and fidelity

The committed corpus contains 40 `.wat` files. `wasm-tools 1.250.0` parses 38 of them into **133** functions containing **1034** instructions. Disrobe lowers all **1034** instructions across all **133** functions, with no instruction-inventory disagreements. Coverage includes the MVP instruction set and the SIMD, atomics, bulk-memory, table/element, reference, and tail-call proposals.

The per-function reference inventory is stored in [`tests/golden/external_wasm_op_inventory.json`](https://github.com/1-3-7/disrobe/blob/main/crates/disrobe-pass-wasm-deob/tests/golden/external_wasm_op_inventory.json), keyed by each fixture's BLAKE3. Instructions count as covered only when their function's recovered WAT reassembles; failed output remains in the denominator. Both tools reject the remaining 2 files, whose reference error text is also pinned.

This coverage measure records successful lowering and reassembly, with an external denominator and a self-reported numerator. The execution comparison below grades behavior separately. Regenerate the reference inventory with:

```sh
cargo test -p disrobe-pass-wasm-deob --test external_op_denominator -- --ignored regenerate_external_inventory
```

Regeneration requires `wasm-tools 1.250.0`. Routine coverage checks use the committed inventory.

All **57** of the 57 execution-eligible functions match the original under Wasmtime over the test's input battery. Eligibility requires a numeric or nullable-reference ABI that can be isolated per function or exercised within a faithful whole module. The `semantic_differential` test compares return values and trap parity; the first 4096 bytes of linear memory also match in all 6 memory cases.

Both sides run with the same limits: 2 MiB per linear memory or GC heap, at most eight linear memories and eight tables, and 1,024 elements per table. Each call receives two million fuel units; an epoch watchdog bounds the comparison. Imported functions trap instead of calling the host.

`wasm deob` runs three family passes before the generic folds. It strips Jscrambler-WASM integrity imports, rewrites Wobfuscator's imported arithmetic operators (`op_add`, `op_xor` and the like) back into instructions and drops an import only when nothing else references it, and inlines Wasmixer's fragmented functions.

A Wobfuscator-style host can also bind the imports under opaque names (`k0`, `k1`) in a JavaScript object. `--host-script` reads that object statically; the script never runs. An entry is re-inlined when it is an exact `i32` operation over its two parameters: `(a, b) => a OP b`, `function (a, b) { return a OP b; }`, the same text inside `eval("...")` or `new Function("a", "b", "return ...")`, an optional `| 0` or `>>> 0` coercion, `Math.imul`, or a call to an `evalN` export whose whole body is one `i32` operator. Every other entry is refused by name in `wobfuscator_host_bindings_refused`: JavaScript `*`, `/` and `%`, which work on doubles, swapped operands of a non-commutative operator, and longer bodies. The reader accepts at most 1 MiB of script and 4,096 entries.

Wasmixer decrypt stubs are run, not rewritten. `wasm deob` finds each XOR byte-walk thunk and calls it by its export name in a wasmtime sandbox with 100 million fuel units, a 2-second epoch deadline, 64 MiB of linear memory and a trapping stub for every import. The decrypted bytes go into `wasmixer_decrypted_literals` with their address, length, hex bytes and UTF-8 text. The module keeps its encrypted data, because rewriting it would make the stub decrypt it a second time at run time. A stub lands in `wasmixer_stubs_unresolved` with its reason when no static data span reaches it, when it is not exported, when it traps or runs out of fuel or memory, or when a cap is hit: 1 MiB per stub, 4 MiB per module and 64 stubs per module.

Tigress flattens a function into a `while (1) switch (next)` loop with arbitrary case labels. The unflattening below rewrites that shape; the detector still classifies the Tigress-via-Emscripten family only from its Emscripten-marked exports, and its `_Z` name helper stays off the run path.

The generic folds keep the module's behaviour. A branch folds only when its condition is a constant expression, or a call into functions that read no mutable global and no memory and do not trap. A `call_indirect` becomes a direct call only when the table slot is an immediate constant, the table is neither exported, imported nor written at run time, and the target's type matches the call's type. The recovered module is validated before it is written; a module that fails validation is reported as `DR-WASMDEOB-0006` instead.

### Control-flow unflattening

`wasm deob` rebuilds control-flow-flattened dispatchers as structured control flow. It recognizes a function that writes a constant start state, enters a `loop`, selects a case with a `br_table` on that state, and branches back to the loop head. Each case ends by writing the next state as a constant. The rewriter reads any module, not only one that matches a detected obfuscator family, and it is separate from the Tigress-via-Emscripten helper named above.

The dispatch state can live in three places. A local holds it, read straight into the `br_table` or copied into a temporary at the loop head. A mutable global holds it, on the condition that the module does not export it and no other function reads or writes it. A linear-memory slot holds it, read at the loop head by a non-atomic `i32.load` at a fixed offset from a base local and written back by a non-atomic `i32.store` to the same memory and offset.

Compiler output reaches that shape in more than one form. When the `br_table` selects on the state plus or minus a constant, as clang emits for case labels that do not start at zero, the case table is shifted by that constant. clang 19 at `-O0` routes every value through its own local, so a dispatcher that does not match as written is matched again after single-use temporaries are forwarded: a local written once from a constant is replaced by that constant at every read that follows the write, and a local written once and read once by the next instruction is dropped. When neither attempt rewrites the function, its original code is restored. The start state can also be written just before the block that holds the dispatch loop, as clang emits for a function with several `return` statements.

Two routes rewrite a recognized dispatcher. The first route applies when the state lives in a local and every case names one successor. It replays the case bodies in execution order, and wraps a repeating tail in a `loop`. The second route rebuilds the state graph as nested `if`/`else` and `loop` blocks. It takes each case that chooses between two successors, and it takes every dispatcher whose state lives in a global or a memory slot. Both routes remove the `br_table` from the rewritten function and stop the state cell from carrying dispatch state. One case keeps the state writes: a stack-frame slot, addressed through a local set once from `global.get; i32.const K; i32.sub`, in a memory that other functions also use. Its writes stay in place so that memory holds the same bytes at every step, and only the dispatch on the slot is removed. `flattened_functions_restructured` counts a function either route rewrote. `flattened_conditional_restructured` counts the second route.

The rewrite is graded by execution. For each fixture pair, `tests/cff_conditional_reloop.rs` first confirms that the flattened module agrees with a separately written module that computes the same function without a dispatcher, over a fixed argument battery under wasmtime. It then requires the rewritten module to agree with that same reference on return value and trap for every argument in the battery. A mutant fixture that swaps the two successors of one conditional transition must disagree with the reference, so a wrong edge cannot pass the battery.

`disrobe` refuses a dispatcher whose shape it cannot resolve. A refused dispatcher stays as it is, the module still validates and behaves as before, and `flattened_dispatchers_walled` records it. Set `DISROBE_DEBUG=wasm-deob` to read the reason on stderr:

- `state cell is observable outside the dispatcher`. The state global is exported or imported, another function reads or writes it, or code after the dispatch loop reads the state cell. A module that carries a function with more nested instruction sequences than the scan bound reports this same reason for every global-state dispatcher in it, because the scan then treats no global as private.
- `state transition is not a resolvable constant edge`. A case does not end in a constant state write, hides that write behind a branch, or reads the state cell in its own work or condition.
- `state graph has no sound structured form`. The state graph has no equivalent shape built from `if`/`else` and `loop`. A cycle entered at two different states or a state the entry cannot reach can land here.
- `dispatcher switch has more targets than the case cap`. The `br_table` has more than 4,096 targets.

An ordinary compiler can emit a shape outside the supported set. `rustc 1.96.1` targeting `wasm32-unknown-unknown` at `-C opt-level=0` lowers a hand-written `match` over a state variable into a next-state temporary. The rewriter admits the recorded dispatcher when it can resolve that temporary's constant edges; its mutation controls remain walled when those edges change. The committed `tests/fixtures/cff_rustc_temp_state.obf.wasm` and its Rust source record that case, and the rewritten output validates and behaves the same as the input under wasmtime.

Tigress-style dispatchers are graded in `tests/wasm_family_recovery.rs` on authored, synthetic fixtures under `corpus/wasm/obf/authored/`, not on Tigress output: three functions written in Tigress's flattened style, compiled by clang 19 (wasi-sdk 25) at `-O0`: one has case labels that start above zero, one calls another, and one leaves through two `return` states. All three are rewritten with no `br_table` left, and the result agrees under wasmtime with a clean build of the same functions at `-O2` over a fixed argument battery. A mutant with one changed case body must disagree. The same file grades the Wobfuscator host table on an authored clang-built module, not Wobfuscator output, with seven opaque operator imports and an authored host script, against a clean build without imports; changing one table entry must make the recovered module disagree. It also checks that the Wasmixer plaintext reaches the report and that a flipped ciphertext byte changes it.

`disrobe auto` reaches the same rewriter through the wasm chain pass. That pass writes `wasm.recovered.wasm` and the real counts in `wasm.recovery.json` when a transformation changed the module. A module whose only finding is a refused dispatcher changes nothing, so its `wasm.recovery.json` carries zeros. Read a refusal from `wasm deob` or from `DISROBE_DEBUG=wasm-deob`, not from the chain sidecar.

## Limits

- Two corpus modules are skipped on wat-parse or signature-extraction failure, so the op-coverage figure covers the supported subset, not all of wasm.
- Functions outside the execution-eligible set are op-coverage-only; their behavior is not compared against the original.
- The Component Model envelope, memory64, and the GC type graph are parsed and decoded by dedicated scanners. Their per-instruction semantics are not all lifted to source. Threads are different: all 67 threads-proposal atomic operators lift to C, Rust, and TypeScript, and the runtime tests grade shared-memory contention, wait and notify, fence, and memory growth under a wall-clock deadline.
- Tigress-style dispatchers are graded on hand-flattened C compiled by clang, not on Tigress output, because Tigress does not run on the build host. Tigress's indirect and call dispatch, its opaque next-state expressions and a condition with `&&` or `||` inside one case are not covered; a case whose transition is not a constant edge is refused.
- A dispatcher whose stack-frame state slot shares its memory with other functions keeps its state stores after the rewrite.
- The Wobfuscator host table is read only from a static object literal with exact `i32` bodies. A table built at run time, or one whose operators work on doubles, is refused entry by entry.
- wasm-name-obfuscator destroys the original debug names. The library's `strip_obfuscated_names` helper removes recognized generated name sections and preserves other custom sections; it cannot restore those names. Its [real-output grader](../../../crates/disrobe-pass-wasm-deob/tests/wasm_name_obfuscator_runner_outputs.rs) compares all 30 pinned outputs with clean wasm-tools references. The helper is separate from the `wasm deob` pipeline, which detects and classifies this family.
- Control-flow unflattening runs only while the module stays under the intra-function folding budget. Above that budget the recovery report sets `intra_function_folding_skipped` and no dispatcher is rewritten.
- A state cell read with an atomic `i32` load is not recognized, so `wasm deob` leaves that function as it stands.
- `flattened_dispatchers_walled` counts dispatchers the rewriter recognized and then refused. A shape it never recognized is not counted, and only the four reasons above are printed.
