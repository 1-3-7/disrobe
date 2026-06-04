| section | line | summary |
|---------|-----:|---------|
| references | 14 | clean-room study sources + licenses |
| elixir-dbgi-ast | 26 | Elixir quoted-AST shape stored in Dbgi metadata |
| erlang-guards | 52 | `when` guard recovery from conditional chains |
| comprehensions | 62 | list/binary comprehension de-desugaring |
| module-attrs | 70 | `-module`/`-export` header emission |
| recovery-measurement | 78 | how with-Dbgi vs no-Dbgi % is measured |
| invariants | 92 | what must hold across changes |

## references

Clean-room study only. No reference source copied; opcode tables and AST
contracts studied, reimplemented in original Rust.

- Erlang/OTP `lib/compiler/src/genop.tab` — generic BEAM opcode table.
  License: Apache-2.0 (Ericsson AB). Studied for opcode semantics.
- Erlang/OTP `lib/stdlib/src/erl_pp.erl` — Erlang abstract-form pretty printer.
  License: Apache-2.0. Studied for surface-form rendering conventions.
- Erlang/OTP `lib/compiler/src/sys_core_fold.erl` — Core Erlang transforms.
  License: Apache-2.0. Studied for comprehension lowering shape.
- Elixir `Macro.to_string` / `Code.quoted_to_algebra` contract (Apache-2.0).
  Studied from the documented quoted-AST grammar, not source (Elixir lives in
  a separate repo, not cloned). The Dbgi `elixir_v1` metadata stores the
  *expanded* quoted AST; renderer reproduces idiomatic Elixir from it.

## elixir-dbgi-ast

Dbgi `{:debug_info_v1, :elixir_erl, <zlib+etf>}` decodes to
`{:elixir_v1, %{definitions: [...], attributes: [...], ...}}`.

Each definition: `{{name, arity}, kind, meta, clauses}` where `kind` is
`def | defp | defmacro | defmacrop`. Each clause:
`{clause_meta, [arg_patterns], guards, body}`.

Quoted-AST node forms (the renderer's contract):
- `{atom, meta, ctx}` with `ctx` an atom -> a *variable* named `atom`.
- `{atom, meta, args_list}` with a list -> a *call* `atom(args...)`.
- `{{:., meta, [mod, fun]}, meta, args}` -> remote call `mod.fun(args...)`.
- 2-tuple literal `{a, b}` -> Elixir 2-tuple; n-tuple -> `{:{}, meta, elems}`.
- atoms/ints/floats/binaries -> literals; the expanded form uses
  `:erlang`/`:maps` remote calls for operators and macro expansions.

## erlang-guards

Core-lifted (no-Dbgi) Erlang: `guard_expr` is synthesized in
`core_erlang::synth_guard` by recovering the `when` conjunction from the
clause's leading type/relational test chain (see `body_lift::clause`).

## comprehensions

`body_lift::comprehension` re-sugars the OTP-lowered recursive helper
(`'-Parent/Arity-lc$^N/M-K-'` / `-lbc$^...`) back to `[Expr || Quals]` and
`<< <<..>> || Quals >>`. Detection keys on the mangled helper-fun name.

## module-attrs

`surface::render_module_header` emits `-module`/`-export` from the Atom +
ExpT tables when Dbgi abstract code is absent.

## recovery-measurement

`tests/elixir_source_recover.rs` and `examples/measure_recovery.rs` token-match
the recovered source against the original corpus `.ex`/`.erl` (independent
ground truth, NOT re-emitted). Two cohorts reported separately:
- with-Dbgi: Elixir megafile (full quoted AST present) -> defs/arities/bodies.
- no-Dbgi: Erlang core-lift (register names absent is the wall).

Token recovery = fraction of original significant tokens (idents, atoms,
operators, keywords) present in recovered output, order-independent at the
definition level.

## invariants

- OTP-26/28/29 + bs_match fixtures stay green.
- No sample is ever executed; only static bytecode is read.
- Elixir Dbgi rendering must stay recompilable-shaped (balanced do/end).
- Register-name wall: no-Dbgi Erlang cannot recover original variable names;
  positional `X0/Y0` names are the honest ceiling there (~75%).
