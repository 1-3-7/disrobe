# WebAssembly

`disrobe` parses WebAssembly modules, lifts them to four target surfaces, reverses Wasm-specific obfuscators, and decodes the Component Model and GC type graphs.

## At a glance

| Layer | Coverage |
|---|---|
| Lift targets | Rust, TypeScript, WAT, or C pseudo-source, or a JSON summary |
| Instruction set | MVP plus the SIMD, atomics, bulk-memory, table/element, reference, and tail-call proposals |
| Name recovery | DWARF and source-map names where debug info is present |
| Op-coverage grade | Every operator in the function lowered, and the re-emitted WAT re-parsed by an independent parser |
| Execution grade | Return values, trap parity, and linear memory compared against the original under wasmtime |
| Obfuscators | Jscrambler-WASM, Wobfuscator, and Wasmixer reversed; Tigress-via-Emscripten and wasm-name-obfuscator detected and classified only |
| Control-flow unflattening | Dispatcher loops whose state lives in a local, a private mutable global, or a non-atomic `i32` memory slot are rebuilt as structured control flow; a dispatcher outside that set is left in place |
| Envelopes | Component Model, threads, memory64, and the GC type graph parsed by dedicated scanners |

## Commands

```sh
disrobe wasm decompile module.wasm --target rust --out lifted.rs
disrobe wasm decompile module.wasm --target ts   --out lifted.ts
disrobe wasm decompile module.wasm --target wat  --out lifted.wat
disrobe wasm decompile module.wasm --target c    --out lifted.c
disrobe wasm decompile module.wasm --target json --out summary.json
disrobe wasm deob module.wasm --out clean.wat --emit-wasm clean.wasm
disrobe wasm component module.wasm        # parse the Component Model envelope -> world / adapter manifest
disrobe wasm types module.wasm            # recover the GC type graph (struct / array / ref types)
```

`decompile` lifts to Rust, TypeScript, WAT, or C pseudo-source, or a JSON summary, with DWARF / source-map name recovery where debug info is present.

`deob` writes the recovered module as WAT to `--out`. Add `--emit-wasm` to write the recovered binary as well. Two JSON files land beside the WAT with its extension replaced, so `--out clean.wat` produces `clean.summary.json` and `clean.recovery.json`. The recovery report holds the per-transformation counts, including the unflattening counts described below.

## Coverage and fidelity

Per-op coverage is measured, not assumed, and it is not divided by a number disrobe produced. `wasm-tools 1.250.0` disassembles each committed `.wat` and its per-function instruction inventory is checked in at [`tests/golden/external_wasm_op_inventory.json`](https://github.com/1-3-7/disrobe/blob/main/crates/disrobe-pass-wasm-deob/tests/golden/external_wasm_op_inventory.json), keyed by each fixture's BLAKE3, so the denominator cannot shrink along with a decoder that stops finding instructions. Against that inventory disrobe lowers **1034** of the **1034** opcodes in the 38 parseable modules, and the two decoders agree instruction for instruction with none unseen. An opcode counts only when its function's re-emitted WAT re-assembles, so output that does not re-parse contributes nothing to the numerator while its instructions stay in the denominator. That covers all **133** of the **133** functions in those 38 parseable modules. The other 2 of the 40 corpus files are rejected by `wasm-tools` as well, and its error text is pinned beside them. The MVP instruction set plus the SIMD, atomics, bulk-memory, table/element, reference, and tail-call proposals are lowered.

Coverage of this kind is not correctness. The denominator is external, but the numerator is still disrobe counting the opcodes it lowered, and a lowering rule firing is not proof the lowering is right, so the figure is published in the self-reported tier. Regenerate the inventory with:

```sh
cargo test -p disrobe-pass-wasm-deob --test external_op_denominator -- --ignored regenerate_external_inventory
```

That regeneration demands `wasm-tools 1.250.0` and fails without it. The check itself reads only the checked-in inventory, so a missing tool can never turn into a pass.

Op-coverage is not the same as execution-equivalence. Separately, all **57** of the 57 execution-eligible functions (a numeric or nullable-reference ABI the harness can isolate per-function or drive as a whole faithful module) are execution-equivalent to the original under wasmtime: the `semantic_differential` test compares return values, trap parity, and linear memory between the original and the recovered module, and 6 are byte-identical in memory.

`wasm deob` reverses three Wasm obfuscator families with byte- or IR-transforming passes: Jscrambler-WASM (strip integrity imports, fold opaque predicates), Wobfuscator (recover the eval op-table and lift each handler), and Wasmixer (unwrap the XOR decrypt stub, defragment). Tigress-via-Emscripten is detected from its Emscripten-marked exports, but `wasm deob` does not run its separate dispatcher-unflattening or `_Z` name helper.

### Control-flow unflattening

`wasm deob` rebuilds control-flow-flattened dispatchers as structured control flow. It recognizes a function that writes a constant start state, enters a `loop`, selects a case with a `br_table` on that state, and branches back to the loop head. Each case ends by writing the next state as a constant. The rewriter reads any module, not only one that matches a detected obfuscator family, and it is separate from the Tigress-via-Emscripten helper named above.

The dispatch state can live in three places. A local holds it, read straight into the `br_table` or copied into a temporary at the loop head. A mutable global holds it, on the condition that the module does not export it and no other function reads or writes it. A linear-memory slot holds it, read at the loop head by a non-atomic `i32.load` at a fixed offset from a base local and written back by a non-atomic `i32.store` to the same memory and offset.

Two routes rewrite a recognized dispatcher. The first route applies when the state lives in a local and every case names one successor. It replays the case bodies in execution order, and wraps a repeating tail in a `loop`. The second route rebuilds the state graph as nested `if`/`else` and `loop` blocks. It takes each case that chooses between two successors, and it takes every dispatcher whose state lives in a global or a memory slot. Both routes remove the `br_table` from the rewritten function and stop the state cell from carrying dispatch state. `flattened_functions_restructured` counts a function either route rewrote. `flattened_conditional_restructured` counts the second route.

The rewrite is graded by execution. For each fixture pair, `tests/cff_conditional_reloop.rs` first confirms that the flattened module agrees with a separately written module that computes the same function without a dispatcher, over a fixed argument battery under wasmtime. It then requires the rewritten module to agree with that same reference on return value and trap for every argument in the battery. A mutant fixture that swaps the two successors of one conditional transition must disagree with the reference, so a wrong edge cannot pass the battery.

`disrobe` refuses a dispatcher whose shape it cannot resolve. A refused dispatcher stays as it is, the module still validates and behaves as before, and `flattened_dispatchers_walled` records it. Set `DISROBE_DEBUG=wasm-deob` to read the reason on stderr:

- `state cell is observable outside the dispatcher`. The state global is exported or imported, another function reads or writes it, or code after the dispatch loop reads the state cell. A module that carries a function with more nested instruction sequences than the scan bound reports this same reason for every global-state dispatcher in it, because the scan then treats no global as private.
- `state transition is not a resolvable constant edge`. A case does not end in a constant state write, hides that write behind a branch, or reads the state cell in its own work or condition.
- `state graph has no sound structured form`. The state graph has no equivalent shape built from `if`/`else` and `loop`. A cycle entered at two different states, a loop with more than one exit, and a state the entry cannot reach all land here.

An ordinary compiler can emit a shape outside the supported set. `rustc 1.96.1` targeting `wasm32-unknown-unknown` at `-C opt-level=0` lowers a hand-written `match` over a state variable into a next-state temporary that is not a resolvable constant edge. The committed `tests/fixtures/cff_rustc_temp_state.obf.wasm` and its Rust source record that case. The dispatcher is refused, the output still validates, and it behaves the same as the input under wasmtime.

`disrobe auto` reaches the same rewriter through the wasm chain pass. That pass writes `wasm.recovered.wasm` and the real counts in `wasm.recovery.json` when a transformation changed the module. A module whose only finding is a refused dispatcher changes nothing, so its `wasm.recovery.json` carries zeros. Read a refusal from `wasm deob` or from `DISROBE_DEBUG=wasm-deob`, not from the chain sidecar.

## Limits

- Two corpus modules are skipped on wat-parse or signature-extraction failure, so the op-coverage figure covers the supported subset, not all of wasm.
- Functions outside the execution-eligible set are op-coverage-only; their behavior is not compared against the original.
- The Component Model envelope, threads, memory64, and the GC type graph are parsed and decoded by dedicated scanners. That is distinct from lifting their per-instruction semantics to source.
- Tigress-via-Emscripten is detected and classified only. Its standalone dispatcher-unflattening and name helpers are not on the `wasm deob` run path.
- A fifth obfuscator family, wasm-name-obfuscator, is detected and its rename strategy classified, but its high-entropy hex renames destroy the original names, so there is nothing to reverse.
- Control-flow unflattening runs only while the module stays under the intra-function folding budget. Above that budget the recovery report sets `intra_function_folding_skipped` and no dispatcher is rewritten.
- A state cell read with an atomic `i32` load is not recognized, so `wasm deob` leaves that function as it stands.
- `flattened_dispatchers_walled` counts dispatchers the rewriter recognized and then refused. A shape it never recognized is not counted, and only the three reasons above are printed.
