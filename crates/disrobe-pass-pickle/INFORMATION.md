| section | line | summary |
|---------|-----:|---------|
| clean-room provenance | 14 | references studied, licenses, what was reimplemented |
| gadget-chain design | 26 | how the deep-safety pass reconstructs call chains |
| measured before/after | 44 | honest recall + false-positive numbers |
| remaining gaps | 56 | obfuscated chains that still slip |

## clean-room provenance

The gadget-chain reconstruction in `safety.rs` (`gadget_chain_patterns` module,
gated behind `AnalysisOptions::deep` / `--deep-safety`) was designed by studying
the analysis *approach* of the following references. None of their source code
was copied; the Rust implementation, the `ResolvedCallable`/`Resolution`
descriptors, the wrapper-unwrap rules, and the confidence tiering are original.

- Trail of Bits `fickling` — `fickling/analysis.py`, `fickling/fickle.py`.
  License: LGPL-3.0. Studied: the gadget taxonomy (`BadCalls`,
  `OvertlyBadEvals`, `non_setstate_calls`, `likely_safe_imports`,
  `UnsafeImports`, `UnusedVariables`), the `UNSAFE_IMPORTS` / `SAFE_BUILTINS`
  frozensets, and the AST-level distinction between *importing* a dangerous
  callable and *invoking* one. Read via `gh api` (no clone left in the tree).
- Public pickle-RCE gadget corpora (getattr/`__import__`/`functools.partial`/
  `operator.attrgetter`/`methodcaller` evasion chains; `__reduce__` /
  `__setstate__` BUILD triggers). Studied for the concrete opcode shapes the
  hand-assembled verification streams reproduce.

## gadget-chain design

The symbolic VM (`vm.rs`) already resolves memo back-references, so a chain
split across `BINGET`/`MEMOIZE` loads is reassembled into one `PickleValue` tree
before analysis. `gadget_chain_patterns::scan` walks that tree and, at every
invocation site (`Reduce` callable, `Object` class for `INST`/`OBJ`/`NEWOBJ`,
and the `BUILD`-triggered `__setstate__` on a stateful `Object`), runs
`resolve_callable` to peel indirection wrappers:

- `getattr(obj, "attr")` -> reconstruct `obj.attr`.
- `__import__("mod")` / `importlib.import_module("mod")` -> module-named callable.
- `functools.partial(fn, ...)` / `apply(fn, ...)` -> unwrap to `fn`.
- `operator.attrgetter` / `methodcaller("attr")` -> attribute callable.

The unwrapped callable is classified against the existing danger list. A name
reached through any wrapper is tiered `PatternInferred`; a name given outright
stays `SignatureCertain`. The default `analyze` path is unchanged
(signature-only); `deep` is additive.

## measured before/after

Measured on a hand-assembled, never-executed opcode corpus (8 malicious gadget
chains incl. direct/partial/getattr-import/nested-partial/setstate, 8 benign
graphs incl. ints/list/dict/str/OrderedDict-NEWOBJ/numpy-reconstruct/partial-int):

- Coarse severity verdict: signature-only recall 8/8, FP 0/8; deep recall 8/8,
  FP 0/8. The top-line verdict does not move on this corpus because each
  malicious sample also surfaces a dangerous *import* the old heuristic already
  flags.
- Where deep adds value (discriminator cases):
  - Precision/attribution: a stream that imports `os.system` but only invokes
    `int(7)` is blunt-flagged OvertlyMalicious by the legacy
    `reduce.dangerous_callable` import-presence heuristic, but produces *zero*
    gadget findings under deep (danger correctly attributed to call sites only).
  - Recall on composed chains: `getattr(__import__("os"), "popen")("id")`, where
    `os.popen` is never a single `GLOBAL`, is reconstructed and flagged
    `PatternInferred` by deep; the fully-qualified name is invisible to a
    pure signature scan of globals.

## remaining gaps

Static, symbolic-only analysis still cannot resolve:

- Runtime string composition of module/attr names (`"o"+"s"`, `bytes.decode`,
  base64/codecs round-trips) feeding `STACK_GLOBAL` - the operands are opaque
  data to the VM, so the chain reads as benign strings.
- Reduce results whose callable is an opaque object returned by another reduce
  we cannot identify (third-party class instances).
- Nested pickle-in-pickle (`pickle.loads` on an inner blob) - the inner stream
  is bytes here; it would need a recursive analysis pass.
- `copyreg.__newobj__` / reconstructor indirection beyond the modelled wrappers.

These are inherent to static opcode analysis and are honestly out of scope for a
symbolic, never-execute design.
