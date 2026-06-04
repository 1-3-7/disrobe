| section | line | summary |
|---------|-----:|---------|
| clean-room provenance | 10 | which ILSpy algorithms were studied and reimplemented from understanding |
| cfg + structurer | 29 | basic-block CFG, dominance, natural loops, structured emission |
| state-machine reversal | 38 | async/iterator detection + MoveNext idiom folding |
| token resolution | 48 | MethodSpec/TypeSpec generic name resolution + arity strip |
| compiler-pattern recovery | 59 | cached-delegate folding, record detection, member annotation |
| metrics | 68 | how the before/after structuring rate is measured |

## clean-room provenance

All control-flow and state-machine recovery in this crate is a clean-room reimplementation of the
*algorithms* used by ILSpy (MIT-licensed), reconstructed from understanding. No ILSpy source was
copied, line-by-line translated, or closely paraphrased. ILSpy was studied only as a scratch clone
outside the repo (`C:/Users/-/AppData/Local/Temp/disrobe-refs/ILSpy`), which is deleted when done.

Algorithms referenced (ILSpy MIT):
- `ICSharpCode.Decompiler/FlowAnalysis/Dominance.cs` - Cooper-Harvey-Kennedy "A Simple, Fast
  Dominance Algorithm" (iterative immediate-dominator dataflow + postorder `intersect`).
- `ICSharpCode.Decompiler/IL/ControlFlow/LoopDetection.cs` - natural-loop recovery from back-edges
  (`h` dominates a predecessor `t` of `h`).
- `ICSharpCode.Decompiler/IL/ControlFlow/ConditionDetection.cs` - `if`/`else` + short-circuit
  `&&`/`||` recovery.
- `ICSharpCode.Decompiler/IL/ControlFlow/YieldReturnDecompiler.cs` - iterator state-machine reversal
  (state field, current backing field, `yield return`/`yield break` folding).
- `ICSharpCode.Decompiler/IL/ControlFlow/AsyncAwaitDecompiler.cs` - async state-machine reversal
  (`IAsyncStateMachine` detection, builder/awaiter fields, `await` folding).

## cfg + structurer

`cfg.rs` builds a basic-block CFG over the branch-normalized CIL stream (leaders = entry, branch
targets, post-branch/return/throw, EH boundaries), computes immediate dominators + a virtual-exit
post-dominator tree, and recovers natural loops. `structure_emit.rs` walks it to emit structured
`while`/`if`-`else`/`switch`/`try`, recovering the `if` follow from post-dominance (with a
reachability fallback when one arm returns/throws), short-circuit `&&`/`||` folding, loop continue
blocks, and return/continue-tail duplication; residual irreducible edges fall back to labeled goto.

## state-machine reversal

`state_machine.rs` classifies compiler-generated async/iterator types by field/method *shape*
(`MoveNext` + a state field + optional builder/current backing fields), so detection is name-agnostic
and survives obfuscation. `state_machine_reverse.rs` folds the lowering idioms in a `MoveNext` body:
`current=x;state=n;return true` -> `yield return x`, `return false` -> `yield break`,
`expr.GetAwaiter()` -> `await expr`, `builder.SetResult(x)` -> `return x`, hoisted `<name>5__N` fields
-> locals, and strips `<>1__state` resume plumbing. Full state-dispatch CFG re-weaving is not yet
done; the await/yield points are surfaced over the still-structural resume skeleton.

## token resolution

`model.rs::resolve_token` resolves the generic-instantiation tables that earlier produced
placeholders. `MethodSpec` (0x2B, parsed in `tables.rs`) resolves through its `MethodDefOrRef` coded
index to the open generic method name (`ConfigureAwait`, `Capture`, `Enumerable.Select`, ...).
`TypeSpec` (0x1B) parses its signature blob via `signature::parse_type_spec_sig`, renders it, and
substitutes the embedded `TypeDef`/`TypeRef` token placeholders, so generic instances render as
`Dictionary<string, int>` etc. `strip_generic_arity` drops the CLI `` `N `` arity suffix. Note: the
`MethodSpec` *arg-count* is intentionally not resolved - doing so regressed async-EH stack accounting
without improving LINQ chains (which underflow upstream either way); only the *name* is resolved.

## compiler-pattern recovery

`closure_reverse.rs` strips the Roslyn cached-delegate caching guard
(`if (!(<>9__N_M)) { <>9__N_M = new D(<>9, <Method>b__N_M); }`) and rewrites cached-delegate
references to the bare lambda method name. `records.rs` detects `record` types via the synthesized
`get_EqualityContract` property and classifies their compiler-generated members; `decompile.rs`
annotates record/state-machine/closure types in method headers so generated boilerplate is
distinguishable from source.

## metrics

`examples/measure_structuring.rs` decompiles `corpus/dotnet/megafile/EdgeCases.baseline.dll` (a real
csc-compiled assembly; ground truth is `EdgeCases.cs`) and reports goto-free %, fully-structured
control-flow-method %, and stack-underflow counts. `examples/dump_state_machines.rs --count` reports
the async/iterator state-machine population. `tests/fixtures/VerifyCases.dll` is a small csc-compiled
fixture for non-circular round-trip inspection. These are honest, non-self-referential metrics: the
baseline DLL is produced by the real Microsoft C# compiler from known source.
