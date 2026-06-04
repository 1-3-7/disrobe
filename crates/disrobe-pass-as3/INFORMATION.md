| section | line | summary |
|---------|-----:|---------|
| references | 12 | studied specs/tools + licenses (clean-room provenance) |
| lifter | 24 | avm2 method-body lifter design + opcode coverage |
| gaps | 40 | known recovery walls (locals, generics, structuring) |
| invariants | 52 | what must hold across changes |

## references

The AVM2 method-body lifter (`src/lifter.rs`) and the constant-pool / ABC
parser (`src/abc.rs`) are an original Rust implementation written from the
public AVM2 opcode semantics and the SWF/ABC binary layout. No third-party
source was pasted, translated, or closely paraphrased.

- Adobe AVM2 Overview (ActionScript Virtual Machine 2), public specification —
  opcode semantics, stack effects, constant-pool layout, multiname kinds.
  Reference only; no text or code reproduced.
- Adobe SWF File Format Specification (v19) — tag layout, DoABC/DoABCDefine.
  Reference only.
- jpexs-decompiler (FFDec), LGPL v3 — studied for AVM2 instruction-set
  coverage breadth (which opcodes appear in real ABC). Clean-room rule: its
  source was NOT copied/translated/paraphrased; only the documented opcode
  semantics (which are spec facts, not FFDec's expression) informed this work.
  No FFDec clone exists in this tree.

## lifter

`lift_body` disassembles a `MethodBody` via `abc::disasm`, then abstractly
interprets the operand stack: `stack: Vec<Expr>`, statements emitted on
side-effecting opcodes (setlocal/setproperty/callpropvoid/return/throw).
Jump targets and exception `target` offsets become `Stmt::Label`; conditional
branches lower to `if (cond) goto Lnn`. Property/call/construct fold the
`findpropstrict name; callprop name` idiom into a bare `name(args)` call.
Class skeletons (`decompile.rs`) resolve method-trait `method_index` to the
matching `MethodBody` and inline the lifted body; constructors use `iinit`.

ABC struct additions to enable this: `TraitInfo.{slot_id,method_index,type_name}`
(previously discarded in `parse_trait`) and `MethodInfo.param_names`
(previously discarded in `parse_method_info`).

## gaps

- Local variable names are post-compile-erased in ABC; non-param slots surface
  as `loc{n}`, param slots reuse `param_names` when present else `arg{n}`.
- Generics are erased by the ActionScript compiler before ABC; `Vector.<T>`
  survives via `TypeName` multinames but user generic type params do not.
- Control flow is emitted as labeled `goto`/`if-goto` pseudocode, not
  re-structured into `if/else/while/for`. Structuring is deliberately deferred
  (correctness risk) and is the main readability delta vs FFDec.
- `hasnext2`/`nextname`/`nextvalue` (for-in iteration) are not folded.

## invariants

- `disasm` operand counts in `abc.rs::opcode_u30_operand_count` must stay in
  sync with the lifter's per-opcode pops/pushes; a mismatch corrupts the stack
  for every following instruction.
- Branch offsets are relative to the instruction AFTER the branch; both
  `collect_labels` and `emit_branch` compute `after + rel`.
- The lifter never executes sample bytecode; it only walks it statically.
