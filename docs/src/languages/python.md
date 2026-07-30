# Python

`disrobe` disassembles and decompiles Python bytecode across CPython 1.0-3.15 and the alternative runtimes, peels source-level obfuscators, and unwraps freezers and protectors back to `.pyc`.

Python is `disrobe`'s most contested and most developed ecosystem. It ships an **in-house Rust decompiler** as the product, never a wrapper around pycdc, pylingual, decompyle3, or uncompyle6. Those tools are benchmark competitors, not selectable fallbacks in the shipped Python decompile command.

## At a glance

| Layer | Coverage |
|---|---|
| Bytecode disassembly | CPython 1.0-3.15, PyPy, MicroPython `.mpy` v0-v6, Jython, IronPython, Brython |
| Decompilation | In-house engine across CPython 1.0-3.15 with per-version opcode dispatch; <!-- m:py_stdlib_full_pct -->95.09%<!-- /m --> per-code-object recompile-equivalence on the full CPython 3.14 stdlib (<!-- m:py_stdlib_full_count -->17378 of 18276<!-- /m -->), <!-- m:py_stdlib_pinned_pct -->96.6%<!-- /m --> on the pinned 200-module corpus (<!-- m:py_stdlib_pinned_count -->6072 of 6286<!-- /m -->, above the 96.60% floor a committed CI gate enforces), and the legacy 1.0-3.7 band asserts a CI floor of <!-- m:py_legacy_count -->150 of 191<!-- /m --> proven-correct (<!-- m:py_legacy_local_count -->166 of 191<!-- /m --> measured locally with the period interpreter zoo: 67 by recompile-equivalence, 99 by structural token-match) |
| Modern constructs | `match`, walrus, f-strings and PEP 750 t-strings, exception groups, PEP 695/696/709 |
| Control flow | try/except/else and try/finally structured from the exception-table forest, with-statement folding, multi-exit `while True` and `while COND` loops, conditional (ternary) expressions, and chained comparisons in conditions, each recompile-checked |
| Freezers | PyInstaller 2.x-6.20+, Nuitka, cx_Freeze, py2exe, PyOxidizer, shiv, pex, Briefcase, SourceDefender |
| Protectors | PyArmor v6-v9-pro and <!-- m:py_source_obfuscators -->20<!-- /m --> source obfuscators with an AST-evaluator backend |

## Commands

```sh
disrobe py decompile module.pyc --out recovered/
disrobe py decompile module.pyc --out recovered/ --backend native    # accepted for explicitness; native is the only backend
disrobe py decompile module.pyc --out recovered/ --emit source,disasm,ast
disrobe py disasm module.pyc --out trace.txt
disrobe py deob obfuscated.py --out clean.py
disrobe py deob obfuscated.py --out clean.py --cleanup
```

`decompile` runs the in-tree engine: a frame-tree pre-pass, per-version opcode dispatch, then round-trip verification. `--backend native` is accepted for explicitness; no external Python decompiler backend is exposed by this command.

`disasm` writes a faithful per-instruction trace across every supported interpreter dialect. This is the Disasm rung: lossless, offset-preserving, no structural reconstruction.

`deob` peels source-level obfuscator wrappers (Kramer/Specter, Berserker, Jawbreaker, BlankOBF, PlusOBF, Wodx, pyobfuscate.com, PyObfuscator (mauricelambert), python-obfuscator (PyPI), ObfuXtreme, Manglify, Oxyry, pyminifier, online obfuscator family, Xindex, pyobfus, Pypacker, Patchwork) with an AST-evaluator backend. `--cleanup` runs a ruff-AST constant-fold and dead-branch-elimination pass afterward.

### Freezers and packagers

```sh
disrobe pyinstaller extract onefile.exe --out out/       # PyInstaller 2.x .. 6.20+, AES-CTR/CFB decrypt
disrobe pyinstaller detect onefile.exe                   # cookie, Python version, TOC offsets, no extract
disrobe pyfreeze extract app.exe --out out/              # cx_Freeze / py2exe / shiv / pex / PyOxidizer / Briefcase
disrobe nuitka detect app.exe                            # flavor + Python version
disrobe nuitka extract app.exe --out out/                # --onefile payload (zstd)
disrobe nuitka symbols app.exe                           # impl_* + module-init scan on --standalone builds
disrobe py sourcedefender app.pye --out app.msgpack      # SourceDefender .pye decrypt
```

### PyArmor

```sh
disrobe pyarmor unpack protected.py --out out/
disrobe pyarmor unpack protected.py --out out/ --allow-dynamic --dynamic-timeout 60
```

`unpack` unpacks a PyArmor wrapper back to its original `.pyc`. v8 and v9-pro are handled by a pure-static path (no code execution). v6/v7 can optionally use a dynamic-hook fallback that runs the obfuscated wrapper in a watched subprocess to capture marshal streams; this is opt-in and unsafe on untrusted input.

> The `--allow-dynamic` path executes the sample. Only enable it on trusted samples or inside an isolated sandbox. See [Forensics and malware-safety posture](../forensics-safety.md).

Other useful flags: `--mode auto|standard|super`, `--target 3.11` (rewrite emitted `.pyc` magic), `--allow-bcc` (BCC native-body lift via Ghidra-headless), `--strict` (exit non-zero on any partial decode), and `--all-emits`.

### End to end

A real-world Python sample is often frozen, then protected, then compiled. `disrobe auto` chains the whole stack:

```sh
disrobe auto suspect.exe --out recovered/    # PyInstaller -> PyArmor -> .pyc decompile
```

## Coverage and fidelity

### How the in-house engine works

1. **Frame-tree pre-pass.** Before walking instructions, the engine reconstructs the nested source-construct tree from the 3.11+ exception table. This eliminates the single-pass stack-walker desync that causes other decompilers to mis-nest try/except and with-blocks.
2. **Provably-inert normalizations.** Twelve normalizations (padding, super-instruction fusion, constant-pool ordering, and more) run before the round-trip check, each gated by an adversarial test proving it masks no real bug.
3. **Round-trip metric.** Every emitted file is recompiled on the matching interpreter and compared opcode-for-opcode against the original. `PERFECT` is byte-identical; `SEMANTIC` is the same program with a different layout; `CODE_DIFF` flags a real bug that is fixed before ship. The normalizer preserves jump-condition polarity rather than collapsing all jumps, so an inverted condition reads as a `CODE_DIFF` instead of passing silently.

### Measured equivalence

The per-code-object figure is measured against an independent oracle, not the tool's own output: each recovered module is recompiled on CPython 3.14.5 and its code objects are diffed against the originals. The full stdlib measurement is **<!-- m:py_stdlib_full_pct -->95.09%<!-- /m -->** (<!-- m:py_stdlib_full_count -->17378 of 18276<!-- /m --> code objects across <!-- m:py_stdlib_full_modules -->574<!-- /m --> modules), and the gate that walks that whole population, `full_stdlib_recompile_gate.rs`, is marked `#[ignore]`: no workflow runs it, so this figure comes from a local run and CI re-derives only a 115-module slice of it, which carries its own floors. On the pinned 200-module corpus (6286 code objects) the rate is **<!-- m:py_stdlib_pinned_pct -->96.6%<!-- /m -->** (<!-- m:py_stdlib_pinned_count -->6072 of 6286<!-- /m -->), above a 96.60% floor a committed CI gate enforces (`arbitrary_recompile_gate.rs`). uncompyle6 stops near 3.8 and decompyle3 near 3.9; the ML-based decompilers self-flag benchmark contamination, and there is no model here to contaminate.

### Cython compiled extensions

A Cython module compiles to a native `.pyd` / `.so`, but the module still exposes the surface CPython needs to import it. The `disrobe-binfmt` Cython reader (`disrobe_binfmt::containers::cython`) recovers that surface from the compiled ELF, PE, or Mach-O: function names, qualified names, docstrings, calling-convention flags, per-class method groupings, and the original `.pyx` / `.pxd` source filenames. It walks the `PyMethodDef` and `PyTypeObject` tables through the module's symbols when they survive, and falls back to a bounded structural scan of the readable data sections for `PyMethodDef`-shaped records when the binary is stripped, resolving data pointers through both static section relocations and ELF dynamic relocations.

Recovery is graded against real compiled Cython fixtures (unstripped, stripped, and separately linked) with a known ground-truth `.pyx`: the expected functions recover with their exact docstrings and signatures, and the report records whether each name came from a symbol or from the structural fallback (`real_cython.rs`).

## Limits

- A Cython module's Python source is gone once compiled. Only the import surface described above is recoverable, not the `.pyx` bodies.
- The legacy 1.0-3.7 band asserts a lower floor in CI than the count measured locally, because the period interpreter zoo the local run uses is not present in CI. Of that local count, 67 are proven by recompile-equivalence and 99 by structural token-match.
- PyArmor v6/v7 may need the opt-in dynamic-hook fallback, which executes the sample. v8 and v9-pro recover on a pure-static path.
