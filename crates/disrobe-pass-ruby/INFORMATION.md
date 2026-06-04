| section | line | summary |
|---------|-----:|---------|
| references | 14 | study-only upstream sources + licenses used for clean-room |
| ibf-body-layout | 24 | verified small_value positions in the iseq body header |
| local-table | 36 | how local names are recovered and the env-offset mapping |
| blocks | 44 | block-parameter recovery from the send block-iseq |
| concatstrings | 50 | string-interpolation boundary heuristic |
| constant-path | 58 | resolving opt_getconstant_path caches to A::B::C |
| gaps | 66 | known fidelity walls (register names, IC types, metaprogramming) |

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

## blocks

A `send`/`opt_send_without_block` carries a block-iseq operand (`-1`/`u32::MAX` when none, e.g.
`&block`/`&:sym` pass-through). When set, the referenced iseq's leading `param.lead_num` local names
are its block parameters, rendered as `recv.method(args) { |a, b| ... }`. Block bodies are not
inlined; the `{ ... }` is a faithful structural marker.

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

## gaps

- Register/name wall: YARV erases names that are not in the `local_table` (block-local temporaries,
  some rescued exception slots). On the megafile ~66% of `getlocal`/`setlocal` operands resolve to a
  real name; the rest stay `local{N}`.
- IC type wall: receiver-class inline caches are cleared on dump, so `opt_send` receivers cannot be
  disambiguated by runtime type; only the constant-path cache survives.
- Metaprogramming wall: `define_method`/`class_eval` bodies are separate iseqs reached through a
  block; the surface is detected and rendered where the method name is a deterministic literal,
  otherwise the dynamic name is left as the recovered expression.
