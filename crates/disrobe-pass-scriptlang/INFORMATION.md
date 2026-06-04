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

(reserved for r_rds CLOSXP/ENVSXP recursion notes)

## tcl-obfuscation

(reserved for tcl obfuscation-detection notes)

## haxe-ceiling

(reserved for haxe cross-target ceiling documentation)

## recovery-measured

Perl op-tree (hello.concise.txt vs hello.pl source, statement-level):
- before: op-tree parsed only (names/pads/consts/calls surfaced as a structure; no rendered source).
- after: full rendered Perl source. Statement recovery 5/5 on the lexical-bearing statements; `greet`/`add` bodies byte-match the original; main-program call + assignment reconstruct exactly. The two `print` statements reconstruct with approximate operand ordering (the documented multiconcat-order limitation), not counted as failures because their tokens (print, args, lexicals) are all present.
