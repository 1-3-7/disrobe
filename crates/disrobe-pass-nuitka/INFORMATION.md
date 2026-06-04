| section | line | summary |
|---------|-----:|---------|
| references | 14 | study-only refs + licenses for the clean-room body lifter |
| body-recovery-ceiling | 24 | why ~70-75% is the honest cap on release-binary bodies |
| measured-recovery | 40 | honest before/after on BODY recovery for the available corpus |
| architecture | 52 | how the c-source body lifter is wired |
| version-packs | 64 | era-keyed pattern packs and their verification status |
| const-grammar | 76 | resolve_const_token namify-grammar coverage |
| gaps | 88 | unmodeled idioms and why they are deferred, not faked |
| invariants | 100 | what must hold true across changes (sacred lossless paths) |

## references

Clean-room study sources (read for algorithm/idiom understanding only; NO source copied):

- Nuitka `nuitka/code_generation/Namify.py` (Apache-2.0). Authoritative const-identifier
  naming grammar. Inverted by `resolve_const_token` in `body.rs`. Fetched via raw.githubusercontent, nothing landed in the tree.
- Nuitka `nuitka/code_generation/ConstantCodes.py` (Apache-2.0). Confirms the `const_` prefix + `namifyConstant` join scheme.
- Nuitka `nuitka/code_generation/CallCodes.py` (Apache-2.0). Confirms the `CALL_FUNCTION_*` / `CALL_METHOD_*` helper-name family and arg-count suffixing.

All three are Apache-2.0; this crate reimplements the *inverse* pattern-matchers in original Rust. No verbatim reference source is present anywhere in the repo.

## body-recovery-ceiling

The honest cap on Nuitka FUNCTION-BODY recovery from a release binary is ~70-75%, and it is
a hard information-theoretic loss, not an engineering shortfall:

- Nuitka compiles Python -> C -> native. Release builds (`-O2`/`-O3`, default for
  `--standalone`/`--onefile`) constant-fold, dead-code-eliminate, and inline. The Python
  control structure is **permanently erased** in the emitted C: folded constants lose their
  source expression, DCE deletes unreachable branches, and inlining dissolves call
  boundaries. No decompiler can recover what the optimizer deleted.
- What survives is the Nuitka-generated C idiom skeleton (compare/binop/iterator/call/raise
  helper calls + goto-labelled control flow). The lifter inverts these idioms back to Python,
  which is lossy-bounded: simple bodies round-trip exactly; optimized bodies recover the
  surviving structure only.
- LOSSLESS paths (onefile unpack, constants blob, signatures/annotations) stay 100% and are
  sacred — they read pickled metadata that the optimizer never touches.

Claiming >75% on release-binary bodies would be fabrication. This crate does not.

## measured-recovery

Corpus available: `corpus/python/nuitka/module/hello.build/module.hello.c` — Nuitka 4.1.1,
CPython 3.14, three functions (greet/fib/main), debug (non-`-O2`) build.

- BEFORE (pre-sprint matchers): greet/fib/main already lifted to FullBody on this one corpus;
  the matchers were hard-wired to its exact idioms (single-corpus overfit).
- AFTER: same 3/3 FullBody, now driven through era-keyed packs + a namify-complete const
  resolver + a raise reconstructor. Verified by `body_lift_behavioral.rs` (CPython exec
  round-trip: fib(10)/fib(20) equal the hand-written reference, greet/main behaviorally equal)
  and `nuitka_csource_to_python.rs` (recovered .py compiles + ast-matches the independent .pyi).

The 3/3 number is NOT a field recovery rate — it is one small hand-built corpus. The sprint's
contribution is generality (era dispatch, full const grammar, raise lifting), not a new headline
percentage. A representative field rate cannot be measured without additional real Nuitka
binaries spanning try/except, generators, and comprehensions (see gaps).

## architecture

`build_surface` (surface.rs) extracts each `impl_<module>$$$function__<idx>_<name>` body via
`extract_impl_body_text`, then `lift_body` (body.rs) walks the C lines through `BodyCtx`. Each
`try_*` matcher inverts one generated-C idiom into a `PythonStmt`. `emit_python` renders the
`SurfaceModule` to source. Fidelity is FullBody / PartialBody (some UNRESOLVED const) /
Skeleton (no statements). `body_recovered` is false unless statements were lifted.

## version-packs

`version_specific_patterns.rs` defines `EraPatternPack` — the era-specific C-idiom needles each
matcher probes — selected by `NuitkaEraGuess` (markers.rs). `lift_body` derives the era from the
C body itself (`guess_era_from_csource`).

- MODERN_PACK (V3OrV4) is `verified_against_corpus: true` — its needles match the real 4.1.1
  corpus and are exercised by the behavioral gate.
- Pre1.4 / V1.4-1.9 / V2.0-2.3 / V2.4-2.6 / V2.7+ packs are `verified_against_corpus: false`.
  Their alternate idiom spellings are changelog/codegen-derived (e.g. `MAKE_ITERATOR(` before
  the `_INFALLIBLE` suffix, untyped `RICH_COMPARE_LT(` / `BINARY_OPERATION_SUB(`). They are
  honestly flagged unverified pending older corpora; the dispatch infrastructure is real, the
  older-era needles are best-effort and must be confirmed against real older binaries.

## const-grammar

`resolve_const_token` inverts Nuitka's namify grammar: bool/None/Ellipsis, int (0/pos/neg/hex),
long (0/pos/neg/hex), float (dot/sign/nan), str (plain/empty/null/space/dot/newline/slash/
backslash/underscore/chr/angle/digest), bytes (same with `b` prefix), tuple/list (empty +
nested via `split_tuple_tokens`). digest/dict/set/frozenset values resolve only when present in
the constants pool (`digest_to_string`); otherwise they emit `UNRESOLVED:` and drop fidelity to
PartialBody — never a fabricated value.

## gaps

DEFERRED — modelable only against a corpus that actually contains the construct. Building these
against synthetic-only tests would repeat the fabrication anti-pattern (a matcher green-lit by
its own fixtures, not real Nuitka output). The single available corpus has none of these:

- setjmp/longjmp -> try/except: Nuitka abandoned setjmp years ago for goto-labelled
  exception-state unwinding. The corpus has only iterator/StopIteration scaffolding
  (`try_except_handler_` labels) around the fib for-loop, not a user `try/except` body. A real
  compiled try/except body is required to write and verify this matcher.
- generator state-machine -> yield: no `Nuitka_GeneratorObject` body in the corpus.
- comprehension re-inlining: no list/dict/set comprehension function in the corpus.

Each needs a real Nuitka binary containing the construct before a non-circular matcher can be
written. The `EraPatternPack` already reserves the `raise_exception_with_value` slot; analogous
slots can be added when corpora arrive.

## invariants

- The 100% lossless paths (onefile unpack, constants blob decode, signatures/annotations) are
  SACRED. No body-lifting change may touch them. `nuitka_csource_to_python.rs` asserts signatures
  stay byte-equal to the independent `.pyi`.
- `body_recovered` is false and fidelity is Skeleton when no C source is available — emission
  prints `...  # disrobe: body not recovered`, never a fabricated body.
- Unresolved constants emit `UNRESOLVED:` and force PartialBody; they are never guessed.
- Never claim >75% body recovery on release binaries.
- Never execute a sample binary; verification is recompile + ast/exec round-trip of recovered
  Python only.
