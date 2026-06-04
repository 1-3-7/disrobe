| section | line | summary |
|---------|-----:|---------|
| references | 18 | study-only upstream sources + licenses used for clean-room |
| recompile-oracle | 30 | non-circular recompile-equivalence harness + measured % |
| ibf-body-layout | 42 | verified small_value positions in the iseq body header |
| local-table | 54 | how local names are recovered and the env-offset mapping |
| nesting | 62 | recursive method/class/module/block body emission |
| control-flow | 70 | branch-offset model; if/else, &&/||/&., while/until |
| concatstrings | 82 | string-interpolation boundary heuristic |
| constant-path | 90 | resolving opt_getconstant_path caches to A::B::C |
| exceptions | 98 | catch_table -> begin/rescue/ensure reconstruction |
| case-when | 108 | dispatch + no-dispatch case/when, fixnum/regexp literals |
| case-in | 116 | case/in pattern matching: value/class/range/bind/guard/else |
| compound-assignment | 130 | ||=/&&= folding |
| gaps | 138 | honest ceilings (structural patterns, []||=, register names) |

## references

Clean-room: the YARV IBF format and opcode semantics were studied from the sources below and
reimplemented in original Rust. No upstream source text is copied into this crate.

- ruby/ruby `compile.c` (`ibf_dump_iseq_each`, `ibf_dump_local_table`, `ibf_dump_ci_entries`,
  `ibf_load_small_value`) — IBF body dump/load order and the `small_value` varint codec.
- ruby/ruby `iseq.c` (`local_var_name`) — env-offset-to-local-table-index mapping.
- ruby/ruby `vm_core.h` (`VM_ENV_DATA_SIZE`) — the fixed env bias on local operands.
- ruby/ruby `insns.def` (`getlocal`/`setlocal`/`concatstrings`/`definemethod`) — operand arity and
  stack effects.
- License: ruby/ruby is dual-licensed under the Ruby License and the 2-clause BSD License (`COPYING`,
  `BSDL`). Only the wire layout and opcode semantics were learned; no code was reproduced.
- Study clone lived in `C:/Users/-/AppData/Local/Temp/disrobe-refs/ruby-src` (Bump v3.4.9,
  `76cca827`) and is deleted after use.

## recompile-oracle

Recovery fidelity is measured non-circularly: the recovered `.rb` is recompiled by the real
`ruby --dump=insns` / `RubyVM::InstructionSequence.compile` and its opcode multiset is diffed against
the opcodes of the fixture's own committed original `.rb` (never re-emitted through our own builder).
The `recover` example prints recovered source for a `.yarvc`. Measured opcode-multiset equivalence on
the 3.4.9 corpus: hello 100% (4/4), greeter 94% (75/79), megafile 79% (whole-file recompiles;
15690/19673). The megafile is a 1677-LOC every-feature stress file; 356/446 methods recover >=70%,
only 3 fully missing. Focused per-feature fixtures recompile near-exactly: case/when 97%, rescue 91%,
op-assign 97%, and `case/in` value/class/bind-guard/else patterns 97-98%.

## ibf-body-layout

The iseq body header is a run of `small_value` varints (`IBF_ISEQ_ENABLE_LOCAL_BUFFER` off in the
shipped build, so every offset resolves against the global object list). Verified positions on the
real 3.4.9 corpus by tracing every `read_small_value` of the greeter body header:
`iseq_size` #1, `bytecode_offset` #2 (`body_offset - stored`), `bytecode_size` #3,
`local_table_offset` #26 (`body_offset - stored`), `ci_entries_offset` #32 (`body_offset - stored`),
`local_table_size` #35, `ci_size` #40. A raw line count of `ibf_dump_iseq_each` differs by one field
from the shipped dump, so positions are anchored empirically, not by source line order.

## local-table

`local_table` is a 4-byte-aligned `ID[local_table_size]` array; each `ID` is a little-endian u32
object-table index resolving to a Symbol whose literal is the local name. Compiler-hidden locals are
dumped as integers (no symbol literal) and surface as `None`. A `getlocal`/`setlocal` operand `op`
maps to slot `local_table_size - (op - VM_ENV_DATA_SIZE) - 1`; out-of-range or hidden slots fall back
to the synthetic `local{N}` placeholder.

## nesting

The decompiler renders the root iseq (index 0) and recurses into child iseqs so method/class/module
and block bodies are emitted inline as real, balanced, recompilable source (not `...` placeholders).
`definemethod`/`definesmethod` emit `def name(params)` + body + `end`; `defineclass` emits
`class`/`module`/`class << self`; a `send` with a block-iseq emits `recv.m(args) { |x| body }` (single
statement) or `recv.m(args) do |x| ... end` (multi-statement). A method name that is itself a Ruby
keyword keeps its explicit `self.` receiver (`self.class`, not bare `class`).

## control-flow

Branch operands are signed runtime-pc relative offsets: `target_pc = next_instr_pc + (offset as
i32)`, mapped to an instruction index by the cumulative `1 + operand_count` pc model. Negative
offsets (backward loop edges) must be read as signed — truncating to `u32::MAX` loses them. Forward
`branchunless`/`branchif` regions structure into `if`/`unless` with `else` arms (jump- or
leave-terminated then-blocks). The `dup; branch{unless,if,nil}; [pop;] rhs` idiom folds to
`lhs && rhs` / `lhs || rhs` / `lhs&.m`. A forward `jump`-to-condition whose region ends in a backward
`branch{if,unless}` to the loop body structures into `while`/`until ... end`.

## concatstrings

`concatstrings n` joins the top `n` stack entries that form a single interpolated string. The
coercion idiom `dup; objtostring; anytostring` is modelled (objtostring identity, anytostring drops
the spare dup) so the interpolated expression survives. When any joined part is a quoted string
literal, the result is rendered as a Ruby interpolation `"...#{expr}..."`, else a `+` concatenation;
`"hello, #{@who}!"` round-trips rather than surfacing as `@who + ... + "!"`.

## constant-path

`opt_getconstant_path` references an inline-cache array dumped as `[len, sym0, sym1, ...]` (each a
symbol object-index). The path is joined with `::` (`[:Tiny, :Greeter]` => `Tiny::Greeter`). The
resolver is strict: a non-symbol element aborts resolution and falls back to `obj[N]`, so no path is
fabricated. Runtime IC *type* state (receiver class for `opt_send`) is reset on `to_binary` dump and
is therefore not statically recoverable; the constant cache is the only deterministic IC win.

## exceptions

The `catch_table` is decoded (`ibf_dump_catch_table`: six `small_value`s per entry —
`iseq_index`/`type`/`start`/`end`/`cont`/`sp`; type is `INT2FIX(n)` so `>> 1` gives RESCUE=1,
ENSURE=2, RETRY=3, BREAK=4, REDO=5, NEXT=6). A RESCUE/ENSURE entry's protected runtime-pc range maps
to instruction indices and wraps in `begin`/`rescue [Class => var]`/`ensure`/`end`; the handler iseq
is decompiled as a `getlocal $!; const; checkmatch; branchunless; [getlocal $!; setlocal var]; <body>;
leave` rescue ladder. The `=> var` binding lives in the parent frame (`setlocal_WC_1`) so it is often
a hidden slot and renders as a bare `rescue Class`.

## case-when

Two forms fold to `case subject; when V; ...; else; ...; end`: (a) literal whens emit
`dup; opt_case_dispatch <hash>, ELSE` then a `<value>; topn 1; ===; branchif WHEN` ladder; (b)
non-literal whens (class/range/regex/lambda) emit the bare `topn/===/branchif` ladder with no jump
table. Fixnum objects decode to their numeric value (`(raw >> 1)`, new bare `NumLiteral` operand) and
Regexp objects to `/source/` (source-string post-pass, slashes escaped).

## case-in

`case/in` pattern matching is recognized by its skeleton: a subject load, an arm ladder of
`dup; <test>; checkmatch 2; branchif ARM`, and a fall-through that either raises
`NoMatchingPatternError` (no `else`) or runs a `pop; pop; <else-body>` (with `else`). Folded forms:
value/constant (`in 1`), class (`in Integer`), range (`in 1..10`), the `=> bind` capture (a `setlocal`
after the test), the `if <guard>` (the expression before the success branch), and the `else` arm. The
`=> bind` and guard may reference a register-erased local (renders `local{N}`, valid + recompilable).
Structural patterns (array `in [a, b]`, find `in [*, x, *]`, hash `in {k:}`, struct `in P(x:)`)
deconstruct via `checktype`/`deconstruct`/`deconstruct_keys`; a case containing any structural arm
returns `None` from the arm parser so the whole case falls back to linear `if`/`else` (never emits an
invalid `in [...]`). See gaps.

## compound-assignment

The `getivar/getlocal; [dup;] branch{if,unless} T; [pop;] <value>; [dup;] set<same target>` idiom
folds to `target ||= value` / `target &&= value`. `n += 1` already round-trips as `n = n + 1`
(identical opcodes). The `[]||=` hash/array form (`dupn 2; opt_aref; ...; opt_aset`) is not yet
reassembled.

## gaps

Honest ceilings on the remaining ~21% megafile opcode gap (all remaining output stays valid,
recompilable Ruby — these constructs are dropped or approximated, never fabricated):

- Register/name wall: YARV erases names absent from the `local_table` (block-local temporaries,
  hidden positional params, rescue `=> e` in the parent frame). They stay `local{N}`/bare (arity and
  structure preserved); name lost. This is genuine bytecode erasure, not a decoder limitation.
- Pattern matching (`case/in`) STRUCTURAL forms: value/class/range/bind/guard/else patterns now fold
  to `case ... in ... end` (fixtures 97-98% opcode-equiv). The remaining gap is array/find/hash/struct
  patterns: their deconstruct ladder (`checktype`/`deconstruct`/`deconstruct_keys`/`opt_aref`/length
  check + `respond_to?` + per-shape error machinery, 100+ insns/arm with an inline fall-through rather
  than a clean `branchif ARM_BODY`) is not reassembled. A mixed case (`classify`: 7 simple arms + array/
  hash arms) bails entirely because any structural arm makes the whole case fall back to linear. The
  `<module:Patterns>` (560 op) / `classify` (273 op) / `deconstruct_point` (159 op) methods drive the
  residual; the element binds are recoverable (`opt_aref N; setlocal var`) but the control-flow
  reconstruction is too version-spanning to land safely without a dedicated pass.
- `[]||=` compound: hash/array-index conditional assignment (`dupn`/`opt_aref`/`opt_aset` dance) is
  tracked for stack balance but not reassembled.
- Loops: only `while`/`until` structure; `for`, `loop`, `begin..end while`, and value-carrying
  `next`/`break`/`redo` are not.
- IC type wall: receiver-class inline caches are cleared on dump, so `opt_send` receivers cannot be
  disambiguated by runtime type; only the constant-path cache survives.
- Metaprogramming: `define_method`/`class_eval` surface with their block bodies; genuinely dynamic
  (eval/binding-derived) names that YARV erased remain the recovered expression.
