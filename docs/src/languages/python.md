# Python

`disrobe` disassembles and decompiles Python bytecode across CPython 1.0-3.15 and the alternative runtimes, peels source-level obfuscators, and unwraps freezers and protectors back to `.pyc`.

Python is `disrobe`'s most contested and most developed ecosystem. It ships an **in-house Rust decompiler** as the product, never a wrapper around pycdc, pylingual, decompyle3, or uncompyle6. Those tools are benchmark competitors, not selectable fallbacks in the shipped Python decompile command.

## At a glance

| Layer | Coverage |
|---|---|
| Bytecode disassembly | CPython 1.0-3.15, PyPy, MicroPython `.mpy` v0-v6, Jython, IronPython, Brython |
| Decompilation | In-house engine across CPython 1.0-3.15 with per-version opcode dispatch; <!-- m:py_stdlib_full_pct -->95.09%<!-- /m --> per-code-object recompile-equivalence on the full CPython 3.14 stdlib (<!-- m:py_stdlib_full_count -->17378 of 18276<!-- /m -->), <!-- m:py_stdlib_pinned_pct -->96.6%<!-- /m --> on the pinned 200-module corpus (<!-- m:py_stdlib_pinned_count -->6072 of 6286<!-- /m -->, above the 96.60% floor a committed CI gate enforces on tag and scheduled runs), and the legacy 1.0-3.7 band asserts a floor, enforced on the same runs, of <!-- m:py_legacy_count -->150 of 191<!-- /m --> proven-correct (<!-- m:py_legacy_local_count -->166 of 191<!-- /m --> measured locally with the period interpreter zoo: 67 by recompile-equivalence, 99 by structural token-match) |
| Modern constructs | `match`, walrus, f-strings and PEP 750 t-strings, exception groups, PEP 695/696/709 |
| Control flow | try/except/else and try/finally structured from the exception-table forest, with-statement folding, multi-exit `while True` and `while COND` loops, conditional (ternary) expressions, and chained comparisons in conditions, each recompile-checked |
| Freezers | PyInstaller 2.x-6.20+, Nuitka, cx_Freeze, py2exe, shiv, pex, PyOxidizer (experimental, unvalidated), Briefcase, SourceDefender |
| Protectors | PyArmor v6-v9-pro, and <!-- m:py_source_obfuscators -->20<!-- /m --> catalogued source obfuscators routed to an AST-evaluator backend; per-family depth is in the catalog |

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
disrobe pyfreeze extract app.exe --out out/              # cx_Freeze / py2exe / shiv / pex / PyOxidizer (experimental, unvalidated) / Briefcase
disrobe nuitka detect app.exe                            # flavor + Python version
disrobe nuitka extract app.exe --out out/                # --onefile payload (zstd)
disrobe nuitka symbols app.exe                           # impl_* + module-init scan on --standalone builds
disrobe py sourcedefender app.pye --out app.msgpack      # SourceDefender .pye decrypt
```

### PyArmor

```sh
disrobe pyarmor unpack protected.py --out out/
disrobe pyarmor unpack protected.py --out out/ --allow-bcc
disrobe pyarmor unpack protected.py --out out/ --allow-dynamic --dynamic-timeout 60
```

`unpack` extracts a decrypted payload and can reconstruct a `.pyc`; reconstructed output is not claimed byte-identical to an original `.pyc`. The published 72/72 result is narrower: it covers manifest-named v8/v9 default-trial wrappers and requires one complete header-anchored root `CodeObject`, not source recovery, emitted `.pyc` identity, semantic or execution equivalence, or external agreement. v6/v7 can optionally use a dynamic-hook fallback that runs the obfuscated wrapper in a watched subprocess to capture marshal streams; this is opt-in and unsafe on untrusted input.

> The `--allow-dynamic` path executes the sample. Only enable it on trusted samples or inside an isolated sandbox. See [Forensics and malware-safety posture](../forensics-safety.md).

Other useful flags: `--mode auto|standard|super`, `--target 3.11` (rewrite emitted `.pyc` magic), `--allow-bcc`, `--strict`, and `--all-emits`.

BCC input is refused with `DR-PYARM-0050` unless `--allow-bcc` is set. With that opt-in, the pass lifts extracted native blobs statically in tree; it does not execute them or invoke Ghidra. Windows x86-64 uses the Microsoft x64 ABI, Linux x86-64 uses the System V ABI, and Darwin ARM64 uses AAPCS64. A function that depends on the PyArmor or CPython runtime dispatch remains an unmodeled record with native disassembly and a typed reason.

The dedicated command writes `bcc/bcc-recovery.json`, `bcc/bcc-pseudo-c.c`, and `bcc/bcc-recovered.py` beneath `--out`. Path-aware PyArmor extraction through `disrobe auto` writes the same three byte-identical artifacts. The canonical JSON schema is `disrobe.pyarmor.bcc.recovery/v1`; it embeds `disrobe.pyarmor.bcc.function_map/1` and represents modeled, unmodeled, and refused blob outcomes. The recovered Python file is a deterministic source skeleton derived from the same publication, not a claim of source identity or execution equivalence.

`--strict` returns `DR-PYARM-0052` when unpacking produces no `.pyc`, records a fallback reason, or records a marshal decode error. It does not add a separate failure condition for incomplete BCC lifting.

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

The per-code-object figure is measured against an independent oracle, not the tool's own output: each recovered module is recompiled on CPython 3.14.5 and its code objects are diffed against the originals. The full stdlib measurement is **<!-- m:py_stdlib_full_pct -->95.09%<!-- /m -->** (<!-- m:py_stdlib_full_count -->17378 of 18276<!-- /m --> code objects across <!-- m:py_stdlib_full_modules -->574<!-- /m --> modules), and the gate that walks that whole population, `full_stdlib_recompile_gate.rs`, is marked `#[ignore]`: no workflow runs it, so this figure comes from a local run and CI re-derives only a 115-module slice of it, which carries its own floors. On the pinned 200-module corpus (6286 code objects) the rate is **<!-- m:py_stdlib_pinned_pct -->96.6%<!-- /m -->** (<!-- m:py_stdlib_pinned_count -->6072 of 6286<!-- /m -->), above a 96.60% floor a committed CI gate enforces on tag and scheduled runs (`arbitrary_recompile_gate.rs`). uncompyle6 stops near 3.8 and decompyle3 near 3.9; the ML-based decompilers self-flag benchmark contamination, and there is no model here to contaminate.

### Per-interpreter bands

Each band compiles the same pinned module list on its own interpreter, then recompiles the recovered source on that same interpreter. A pinned module an interpreter does not ship is not measured, so the denominators differ and the rates do not rank the bands against each other. Every rate below is cut from the fraction beside it.

| Band | Interpreter | Recovered | Rate | Modules | Enforced on |
|---|---|---|---|---|---|
| 3.10 | CPython <!-- m:py_band_310_interpreter -->3.10.20<!-- /m --> | <!-- m:py_band_310_frac -->5224 / 5458<!-- /m --> code objects | <!-- m:py_band_310_rate -->95.71%<!-- /m --> | <!-- m:py_band_310_modules -->161<!-- /m --> | push, tag, schedule |
| 3.11 | CPython <!-- m:py_band_311_interpreter -->3.11.15<!-- /m --> | <!-- m:py_band_311_frac -->5433 / 5638<!-- /m --> code objects | <!-- m:py_band_311_rate -->96.36%<!-- /m --> | <!-- m:py_band_311_modules -->172<!-- /m --> | tag, schedule |
| 3.12 | CPython <!-- m:py_band_312_interpreter -->3.12.13<!-- /m --> | <!-- m:py_band_312_frac -->5404 / 5659<!-- /m --> code objects | <!-- m:py_band_312_rate -->95.49%<!-- /m --> | <!-- m:py_band_312_modules -->177<!-- /m --> | tag, schedule |
| 3.13 | CPython <!-- m:py_band_313_interpreter -->3.13.14<!-- /m --> | <!-- m:py_band_313_frac -->5717 / 5966<!-- /m --> code objects | <!-- m:py_band_313_rate -->95.83%<!-- /m --> | <!-- m:py_band_313_modules -->190<!-- /m --> | tag, schedule |
| 3.14 | CPython <!-- m:py_band_314_interpreter -->3.14.5<!-- /m --> | <!-- m:py_band_314_frac -->6072 / 6286<!-- /m --> code objects | <!-- m:py_band_314_rate -->96.60%<!-- /m --> | <!-- m:py_band_314_modules -->200<!-- /m --> | no band gate, mirrored |
| 3.15 | CPython <!-- m:py_band_315_interpreter -->3.15.0b4<!-- /m --> | <!-- m:py_band_315_frac -->6219 / 6480<!-- /m --> code objects | <!-- m:py_band_315_rate -->95.97%<!-- /m --> | <!-- m:py_band_315_modules -->199<!-- /m --> | tag, schedule |
| 1.0 to 3.7 | period interpreter zoo | <!-- m:py_legacy_frac -->150 / 191<!-- /m --> fixtures | floor, not a measured rate | not applicable | tag, schedule |

Every figure in the table renders from `xtask/data/recovery.json`, so moving a bar without regenerating the page fails `cargo run -p xtask -- regen --check`.

The last column names the CI triggers that run each row. A push to `main` runs the 3.10 band, the smallest population, which keeps the push route inside its time budget. A tag build and the weekly scheduled build run every row that has a band gate. The 3.10 and 3.15 jobs mark their interpreter mandatory, so a runner that cannot provide it fails the job instead of reporting a pass over nothing.

Two rows read differently from the rest. No workflow measures a 3.14 band, and `xtask/src/facts.rs` records that bar as unpinned. The row re-plots the 200-module pinned corpus measurement, `regen --check` holds the two bars equal on every run, and `arbitrary_recompile_gate.rs` measures the bar it mirrors on tag and scheduled runs. The legacy row counts fixtures rather than code objects, and its fraction is the floor `legacy_recompile.rs` asserts rather than a measured rate, so it carries no rate.

### Cython compiled extensions

A Cython module compiles to a native `.pyd` / `.so`, but the module still exposes the surface CPython needs to import it. The `disrobe-binfmt` Cython reader (`disrobe_binfmt::containers::cython`) recovers that surface from the compiled ELF, PE, or Mach-O: function names, qualified names, docstrings, calling-convention flags, per-class method groupings, and the original `.pyx` / `.pxd` source filenames. It walks the `PyMethodDef` and `PyTypeObject` tables through the module's symbols when they survive, and falls back to a bounded structural scan of the readable data sections for `PyMethodDef`-shaped records when the binary is stripped, resolving data pointers through both static section relocations and ELF dynamic relocations.

Recovery is graded against real compiled Cython fixtures (unstripped, stripped, and separately linked) with a known ground-truth `.pyx`: the expected functions recover with their exact docstrings and signatures, and the report records whether each name came from a symbol or from the structural fallback (`real_cython.rs`).

## Limits

- A Cython module's Python source is gone once compiled. Only the import surface described above is recoverable, not the `.pyx` bodies.
- The legacy 1.0-3.7 band asserts a lower floor on tag and scheduled runs than the count measured locally, because the period interpreter zoo the local run uses is not present in CI. Of that local count, 67 are proven by recompile-equivalence and 99 by structural token-match.
- PyArmor v6/v7 may need the opt-in dynamic-hook fallback, which executes the sample. The manifest-named v8/v9 default-trial result is a pure-static structural decoding check only; it does not establish recovery for other variants.
