# Python

`disrobe` disassembles and decompiles Python bytecode across CPython 1.0-3.15 and the alternative runtimes, peels source-level obfuscators, and unwraps freezers and protectors back to `.pyc`.

The Python decompiler is implemented in Rust. The command uses this engine; pycdc, PyLingual, decompyle3, and uncompyle6 appear in comparison benchmarks.

## At a glance

| Layer | Coverage |
|---|---|
| Bytecode disassembly | CPython 1.0-3.15, PyPy, MicroPython `.mpy` v0-v6, Jython, IronPython, Brython |
| Decompilation | CPython 1.0-3.15 with per-version opcode dispatch. Normalized opcode-structure agreement on CPython 3.14.5: <!-- m:py_stdlib_full_count -->17396 of 18276<!-- /m --> code objects in a fixed core population; <!-- m:py_stdlib_pinned_count -->6077 of 6286<!-- /m --> in its pinned 200-module subset. See the measurement definition below. |
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

The engine reconstructs nested source constructs from the CPython 3.11+ exception table before walking instructions. Its round-trip checker recompiles recovered source when a matching interpreter is available, then compares the resulting code objects. Reports distinguish exact matches, normalized matches, code differences, compilation failures, and an unavailable interpreter. A normalized match is evidence about the compared representation, not a proof of identical behavior.

### Measured opcode structure

The benchmark compiles each original module and its recovered source with CPython 3.14.5 at optimization level zero. It compares normalized opcode streams and three argument-count fields for each original code object. Normalization removes or merges selected instructions and omits jump targets and most operands. The comparison excludes `__annotate__` code objects and does not penalize additional recovered code objects. These results measure opcode structure, not bytecode identity or program equivalence.

The fixed core population contains <!-- m:py_stdlib_full_modules -->574<!-- /m --> modules and excludes `idlelib` and `turtledemo`: **<!-- m:py_stdlib_full_count -->17396 of 18276<!-- /m -->** code objects agree, or **<!-- m:py_stdlib_full_pct -->95.18%<!-- /m -->**. Its pinned 200-module subset yields **<!-- m:py_stdlib_pinned_count -->6077 of 6286<!-- /m -->** (**<!-- m:py_stdlib_pinned_pct -->96.67%<!-- /m -->**). The committed module lists define both populations.

`full_stdlib_recompile_gate.rs` measures the 574-module population on explicit invocation. CI runs a 115-module subset and runs the 200-module gate on tags and scheduled builds, with a 96.67% regression threshold for the latter.

The [recorded run](https://github.com/1-3-7/disrobe/blob/main/evidence/results/captured/python-stdlib-full.json)
includes the executable and interpreter hashes, comparison rules, exact counts, and reproduction
command. Its [unmatched objects](https://github.com/1-3-7/disrobe/blob/main/evidence/results/captured/python-stdlib-full.nonmatching.tsv)
identify all 880 code differences, missing objects, and collisions by module, qualified name, and occurrence.

### Per-interpreter bands

Each band uses the same normalized opcode-structure comparison and pinned module list, compiling both sources on the listed interpreter. Modules absent from that interpreter are excluded. The different denominators prevent a direct ranking between bands.

| Band | Interpreter | Recovered | Rate | Modules | Enforced on |
|---|---|---|---|---|---|
| 3.10 | CPython <!-- m:py_band_310_interpreter -->3.10.20<!-- /m --> | <!-- m:py_band_310_frac -->5229 / 5458<!-- /m --> code objects | <!-- m:py_band_310_rate -->95.80%<!-- /m --> | <!-- m:py_band_310_modules -->161<!-- /m --> | push, tag, schedule |
| 3.11 | CPython <!-- m:py_band_311_interpreter -->3.11.15<!-- /m --> | <!-- m:py_band_311_frac -->5442 / 5638<!-- /m --> code objects | <!-- m:py_band_311_rate -->96.52%<!-- /m --> | <!-- m:py_band_311_modules -->172<!-- /m --> | tag, schedule |
| 3.12 | CPython <!-- m:py_band_312_interpreter -->3.12.13<!-- /m --> | <!-- m:py_band_312_frac -->5420 / 5659<!-- /m --> code objects | <!-- m:py_band_312_rate -->95.77%<!-- /m --> | <!-- m:py_band_312_modules -->177<!-- /m --> | push, tag, schedule |
| 3.13 | CPython <!-- m:py_band_313_interpreter -->3.13.14<!-- /m --> | <!-- m:py_band_313_frac -->5732 / 5966<!-- /m --> code objects | <!-- m:py_band_313_rate -->96.07%<!-- /m --> | <!-- m:py_band_313_modules -->190<!-- /m --> | push, tag, schedule |
| 3.14 | CPython <!-- m:py_band_314_interpreter -->3.14.5<!-- /m --> | <!-- m:py_band_314_frac -->6077 / 6286<!-- /m --> code objects | <!-- m:py_band_314_rate -->96.67%<!-- /m --> | <!-- m:py_band_314_modules -->200<!-- /m --> | no band gate, mirrored |
| 3.15 | CPython <!-- m:py_band_315_interpreter -->3.15.0b4<!-- /m --> | <!-- m:py_band_315_frac -->6227 / 6480<!-- /m --> code objects | <!-- m:py_band_315_rate -->96.09%<!-- /m --> | <!-- m:py_band_315_modules -->199<!-- /m --> | tag, schedule |
| 1.0 to 3.7 | matching legacy interpreter when available | <!-- m:py_legacy_frac -->150 / 191<!-- /m --> fixtures | floor, not a measured rate | not applicable | tag, schedule |

The recorded results and interpreter versions are in `xtask/data/recovery.json`.

The 3.10, 3.12, and 3.13 bands run on each push to `main`. Tag builds and weekly scheduled builds also run the remaining band gates. The dedicated 3.10, 3.12, 3.13, 3.14, and 3.15 checks require their pinned interpreters.

Two rows read differently from the rest. The 3.14 row reports the pinned 200-module subset of the accepted 574-module measurement; both use the same source hashes and comparison rules. The legacy row counts fixtures rather than code objects, and its fraction is the floor `legacy_recompile.rs` asserts rather than a measured rate, so it carries no rate.

### Cython compiled extensions

A Cython module compiles to a native `.pyd` / `.so`, but the module still exposes the surface CPython needs to import it. The `disrobe-binfmt` Cython reader (`disrobe_binfmt::containers::cython`) recovers that surface from the compiled ELF, PE, or Mach-O: function names, qualified names, docstrings, calling-convention flags, per-class method groupings, and the original `.pyx` / `.pxd` source filenames. It walks the `PyMethodDef` and `PyTypeObject` tables through the module's symbols when they survive, and falls back to a bounded structural scan of the readable data sections for `PyMethodDef`-shaped records when the binary is stripped, resolving data pointers through both static section relocations and ELF dynamic relocations.

Recovery is graded against real compiled Cython fixtures (unstripped, stripped, and separately linked) with a known ground-truth `.pyx`: the expected functions recover with their exact docstrings and signatures, and the report records whether each name came from a symbol or from the structural fallback (`real_cython.rs`).

## Limits

- A Cython module's Python source is gone once compiled. Only the import surface described above is recoverable, not the `.pyx` bodies.
- The legacy 1.0-3.7 gate requires at least 150 of 191 committed fixtures. It uses bytecode recompilation when a matching interpreter is available and structural token comparison otherwise.
- PyArmor v6/v7 may need the opt-in dynamic-hook fallback, which executes the sample. The manifest-named v8/v9 default-trial result is a pure-static structural decoding check only; it does not establish recovery for other variants.
