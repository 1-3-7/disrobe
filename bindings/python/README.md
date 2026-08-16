# disrobe Python bindings

Programmatic Python API for the [disrobe](https://github.com/1-3-7/disrobe)
deobfuscator + decompiler suite. The bindings wrap the same Rust library
code the `disrobe` CLI uses, exposed as the importable `disrobe` Python
module via pyo3 (abi3, Python 3.9+).

## Install (from source)

```sh
git clone https://github.com/1-3-7/disrobe
cd disrobe/bindings/python
pip install maturin
maturin develop --release
```

For a wheel build without local install:

```sh
maturin build --release
pip install target/wheels/disrobe-*.whl
```

## Use

```python
import disrobe

# auto chain: detect + run all matching passes up to depth 8
with open("suspect.exe", "rb") as f:
    plan = disrobe.auto(f.read(), max_depth=8)
print(plan["stats"], plan["nodes"])

# native python decompile (CPython 1.0 - 3.15, PyPy)
with open("module.pyc", "rb") as f:
    result = disrobe.py_decompile(f.read(), roundtrip=True)
print(result["source"])
print(result["roundtrip"]["status"])  # 'perfect' | 'semantic' | 'code-diff' | ...

# pyarmor static unpack (v6/v7/v8/v9)
with open("dist/pyarmor_runtime.so", "rb") as f:
    report = disrobe.pyarmor_unpack(f.read())
print(report["status"], report["plaintext_blake3_hex"])

# js obfuscator family detect + unbundle
det = disrobe.js_detect(open("main.js").read())
modules = disrobe.js_unbundle(open("bundle.js").read())  # auto bundler
```

See `help(disrobe)` for the full function list & per-function docstrings.

## Function surface

| Category | Functions |
|---|---|
| auto | `auto` |
| python | `py_decompile`, `py_disasm`, `py_deob`, `py_deob_detect`, `py_deob_list_passes`, `py_deob_detect_pass` |
| pyarmor | `pyarmor_detect`, `pyarmor_unpack` |
| pyinstaller | `pyinstaller_extract`, `pyinstaller_entry_bytes` |
| nuitka | `nuitka_detect`, `nuitka_extract` |
| hermes (react-native) | `hermes_disasm`, `hermes_lift`, `hermes_info` |
| mach-o | `macho_dump` |
| jvm / android | `jvm_parse_class`, `jvm_parse_dex`, `jvm_decompile_class`, `jvm_decompile_dex`, `jvm_detect`, `jvm_backends` |
| .net | `dotnet_parse_pe`, `dotnet_parse_metadata`, `dotnet_detect`, `dotnet_analyze`, `dotnet_decompile`, `dotnet_recover_decoders`, `dotnet_backends` |
| wasm | `wasm_analyze`, `wasm_detect` |
| js | `js_detect`, `js_unminify`, `js_unbundle` |
| native | `native_format`, `native_detect`, `native_probe_backends` |
| pickle | `pickle_disasm`, `pickle_decompile`, `pickle_safety`, `pickle_trace`, `pickle_polyglot`, `pickle_ml_detect` |
| envelope | `envelope_create`, `envelope_verify` |
| generic dispatch | `disasm`, `parse`, `compile` |
| llm renders | `agents_md`, `skill_md` |

All functions raise `disrobe.DisrobeError` on failure; `disasm`/`parse`/`compile` raise `disrobe.UnsupportedLanguage` (a `DisrobeError` subclass) for languages without a backing implementation.

Full per-function reference: the [Python bindings chapter](https://1-3-7.github.io/disrobe/python-bindings.html) of the docs.
