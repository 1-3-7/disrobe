| section | line | summary |
|---------|-----:|---------|
| references | 14 | clean-room study sources + licenses per language |
| perl-decompile | 28 | op-tree to source reconstruction, name wall |
| r-closures | 44 | ENVSXP/CLOSXP recursion, lossless body recovery |
| tcl-obfuscation | 56 | indirect-call / proc-inline / subst detection |
| haxe-ceiling | 66 | cross-target fingerprint-only, route-not-reimplement |
| recovery-measured | 78 | honest before/after per language |

## references

All study-only. No reference source was copied; structures were reimplemented from spec in original Rust.

- Perl `B::Concise` / `B::Concise` op-tree node format and op names: perldoc.perl.org/B::Concise (Perl 5, Artistic/GPL dual). Studied the seq/arity/op-name layout and pad-vs-global semantics only.
- Perl `B::Bytecode` / `ByteLoader` PLBC stream layout: perldoc B::Bytecode (Perl 5, Artistic/GPL). Header + opcode framing reimplemented in `perl_bytecode.rs`.
- R internals serialization (RDS/XDR SEXPTYPE tags, CLOSXP/ENVSXP layout): cran.r-project.org R Internals manual (GPL-2/GPL-3). SXP tag constants reimplemented in `r_rds.rs`.
- Tcl bytecode / starkit (Metakit + zipvfs) container layout: tcl.tk wiki + Metakit format notes (Tcl/Tk BSD-style license). Container scan reimplemented in `tcl.rs`.
- Haxe target emission (js banner, HLB magic, SWF, jvm/cil/hxcpp): haxe.org manual (MIT). Fingerprint markers only.

Licenses recorded for provenance; none of these grant reuse of source text, and none was reused. All decoders are original.

## perl-decompile

`perl_decompile.rs` `DecompileWalker` walks a parsed `PerlOpTree` (from `perl.rs`) and emits readable Perl SOURCE.
Statement segmentation: split each sub's op list on `nextstate`/`dbstate` COP boundaries. Per-segment reconstruction:
- `my (...) = @_;` signatures from the `aassign` + `gv[*_]` + `padrange`/`padsv` pattern (pad names survive).
- `return EXPR;` from `return`/`leavesub`, where EXPR is recovered from `multiconcat` template (interpolation), `const` literal, or a binary-arith op over two pad operands.
- `my $x = name(args);` and bare `name(args);` calls from `entersub` + `gv[*name]` + const/pad args.
- `print ...;` from the print listop.

NAME WALL (honest, ~75% ceiling): lexical (pad) names like `$name`, `$a`, `$b`, `$msg` survive in the op-tree pad and reconstruct verbatim. Package-global temporaries and intermediate compiler temps are erased — those surface as honest `# <expression erased>` markers and lower `recovery_ratio`. multiconcat operand-vs-literal ORDER is only partially recoverable from the B::Concise text template, so `print` arg ordering is approximate (e.g. `print "\n$msg"` vs original `print "$msg\n"`), while lexical-bearing sub bodies (`greet`, `add`) reconstruct exactly.

## r-closures

`r_rds.rs` `recurse_closure()` structurally decodes a CLOSXP into `RdsClosure { formals, body, environment, rendered }`.
R serializes closures LOSSLESSLY (R Internals): flags, attrib?, tag = CLOENV, car = FORMALS pairlist, cdr = BODY language object.
- formals: tagged pairlist; each tag symbol = parameter name, value = default expr or `MISSINGARG_SXP` (251) for no default.
- body: a LANGSXP call tree, deparsed by `render_call` (binary operators like `+ - * / ^` rendered infix, `{` blocks, generic `f(args)` calls).
- environment: ENVSXP read via `read_environment` (locked, enclos, frame, hashtab, attr); frame binding tag-names captured; singleton envs (GLOBALENV 253 / EMPTYENV 242 / BASEENV 241 / BASENAMESPACE 250) recognized as references.

REFERENCE TABLE: a unified `Walk.ref_table` is threaded through BOTH the flat `walk_item` and structured `read_rvalue`. Symbols and non-singleton environments claim a ref slot on first write; REFSXP (255) resolves via the packed index (`flags >> 8`, or a trailing u32 when 0). This is what lets a symbol used in both formals and body (e.g. `x`, `y`) resolve back to its name on the second occurrence. Slot order: SYMSXP pushes after printname; ENVSXP pushes BEFORE its contents (so it can self-reference). MISSINGARG/UNBOUNDVALUE/singleton-env tokens consume no extra bytes.

Verified non-circularly in `tests/real_r_closure.rs` against hand-encoded R wire bytes (the documented format, not a decoder re-emit): `function(x, y) x + y` -> formals [x, y], body `x + y`; `function(n = 1) n * 2` -> default `1`, body `n * 2`. R is lossless once implemented: formals/body/env all recover exactly (no name wall, unlike Perl).

## tcl-obfuscation

`tcl.rs` `analyze_obfuscation()` scans every extracted `.tcl`/`.tm` member's UTF-8 source for three idiom families:
- indirect-call: `eval`, `interp eval`, `namespace eval/inscope`, `uplevel`, `apply`, `tailcall`, `coroutine`.
- dynamic-proc: `proc [`, `proc $`, `proc {*}`, `rename`, `interp alias` (proc name/body computed at runtime).
- subst-codegen: `subst`, `string map`, `regsub`, `binary scan/format`, `encoding convertfrom`, `base64::decode`.
`obfuscated` flips true only when total hits >= 3 AND at least two distinct families fire, so ordinary `proc`/`puts`/`expr` source is not flagged. Per-hit file + marker + count retained in `hits`.

`measure_completeness()` reports `declared_entries`, `recovered_with_contents` (non-empty payload), `tcl_source_files`, and a `ratio()`. ZipVfs starkits recover bytes in full (ratio 1.0). Metakit/sdx.kit recovery is FILENAME-ONLY (the Metakit b-tree blob is not decompressed), so `recovered_with_contents` is 0 and the ratio is honest about it (~0.0) — flagged in `tests/real_tcl_starkit.rs::real_metakit_completeness_is_honest_about_filename_only_recovery`.

Verified in tcl.rs unit tests (obfuscated multi-idiom loader flagged; clean source not) and against real hello.kit (clean, complete) / sdx.kit (Metakit, filename-only) fixtures.

## haxe-ceiling

(reserved for haxe cross-target ceiling documentation)

## recovery-measured

Perl op-tree (hello.concise.txt vs hello.pl source, statement-level):
- before: op-tree parsed only (names/pads/consts/calls surfaced as a structure; no rendered source).
- after: full rendered Perl source. Statement recovery 5/5 on the lexical-bearing statements; `greet`/`add` bodies byte-match the original; main-program call + assignment reconstruct exactly. The two `print` statements reconstruct with approximate operand ordering (the documented multiconcat-order limitation), not counted as failures because their tokens (print, args, lexicals) are all present.
