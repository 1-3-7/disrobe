# Python

Python is **disrobe**'s most contested and most developed ecosystem. It ships an **in-house Rust decompiler** as the product - never a wrapper around pycdc, pylingual, decompyle3, or uncompyle6 (those are benchmark competitors, available only as optional `--backend` fallbacks).

## At a glance

| Layer | Coverage |
|---|---|
| Bytecode disassembly | CPython 1.0-3.15, PyPy, MicroPython `.mpy` v0-v6, Jython, IronPython, Brython |
| Decompilation | In-house engine across CPython 1.0-3.15 with per-version opcode dispatch |
| Modern constructs | `match`, walrus, f-strings and PEP 750 t-strings, exception groups, PEP 695/696/709 |
| Freezers | PyInstaller 2.x-6.20+, Nuitka, cx_Freeze, py2exe, PyOxidizer, shiv, pex, Briefcase, SourceDefender |
| Protectors | PyArmor v6-v9-pro and 14 source obfuscators with an AST-evaluator backend |

## Decompiling `.pyc`

```sh
disrobe py decompile module.pyc --out recovered/
disrobe py decompile module.pyc --out recovered/ --backend native    # default; deterministic, no external tools
disrobe py decompile module.pyc --out recovered/ --emit source,disasm,ast
```

The default `native` backend is the in-tree engine: it runs a frame-tree pre-pass, per-version opcode dispatch, and then round-trip verification. The optional `--backend pycdc|decompyle3|uncompyle6` flags shell out to those external tools (which must be on `PATH`) purely for benchmark comparison; they are never the default.

### How the in-house engine works

1. **Frame-tree pre-pass.** Before walking instructions, the engine reconstructs the nested source-construct tree from the 3.11+ exception table. This eliminates the single-pass stack-walker desync that causes other decompilers to mis-nest try/except and with-blocks.
2. **Provably-inert normalizations.** Twelve normalizations (padding, super-instruction fusion, constant-pool ordering, and more) run before the round-trip check, each gated by an adversarial test proving it masks no real bug.
3. **Round-trip metric.** Every emitted file is recompiled on the matching interpreter and compared opcode-for-opcode against the original. `PERFECT` is byte-identical; `SEMANTIC` is the same program with a different layout; `CODE_DIFF` flags a real bug that is fixed before ship.

## Disassembling

```sh
disrobe py disasm module.pyc --out trace.txt
```

A faithful per-instruction trace across every supported interpreter dialect. This is the Disasm rung - lossless, offset-preserving, no structural reconstruction.

## Deobfuscating source

```sh
disrobe py deob obfuscated.py --out clean.py
disrobe py deob obfuscated.py --out clean.py --cleanup
```

Peels source-level obfuscator wrappers - Hyperion, Kramer, Berserker, Jawbreaker, BlankOBF, PlusOBF, wodx, oxyry, pyminifier, manglify, pyobfuscate.com, and others - with an AST-evaluator backend. `--cleanup` runs a ruff-AST constant-fold and dead-branch-elimination pass afterward.

## Freezers and packagers

```sh
disrobe pyinstaller extract onefile.exe --out out/       # PyInstaller 2.1 .. 6.x, AES-CTR/CFB decrypt
disrobe pyinstaller detect onefile.exe                   # cookie, Python version, TOC offsets, no extract
disrobe pyfreeze extract app.exe --out out/              # cx_Freeze / py2exe / shiv / pex / PyOxidizer / Briefcase
disrobe nuitka detect app.exe                            # flavor + Python version
disrobe nuitka extract app.exe --out out/                # --onefile payload (zstd)
disrobe nuitka symbols app.exe                           # impl_* + module-init scan on --standalone builds
disrobe py sourcedefender app.pye --out app.msgpack      # SourceDefender .pye decrypt
```

## PyArmor

```sh
disrobe pyarmor unpack protected.py --out out/
```

Unpacks a PyArmor wrapper back to its original `.pyc`. v8 and v9-pro are handled by a pure-static path (no code execution). v6/v7 can optionally use a dynamic-hook fallback that runs the obfuscated wrapper in a watched subprocess to capture marshal streams - this is opt-in and unsafe on untrusted input:

```sh
disrobe pyarmor unpack protected.py --out out/ --allow-dynamic --dynamic-timeout 60
```

> The `--allow-dynamic` path executes the sample. Only enable it on trusted samples or inside an isolated sandbox. See [Forensics and malware-safety posture](../forensics-safety.md).

Other useful flags: `--mode auto|standard|super`, `--target 3.11` (rewrite emitted `.pyc` magic), `--allow-bcc` (BCC native-body lift via Ghidra-headless), `--strict` (exit non-zero on any partial decode), and `--all-emits`.

## End-to-end

A real-world Python sample is often frozen, then protected, then compiled. `disrobe auto` chains the whole stack:

```sh
disrobe auto suspect.exe --out recovered/    # PyInstaller -> PyArmor -> .pyc decompile
```
