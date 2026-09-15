# disrobe Python bindings

Use Disrobe's Rust recovery engines from Python to decompile bytecode, inspect
compiled software, deobfuscate scripts, and extract packaged files. The `disrobe`
module supports Python 3.9+ and returns report objects with typed attributes.

## Install from source

Install Python 3.9+, the repository's Rust toolchain, and the target's native
compiler and linker. On Windows with the MSVC target, install the Visual C++
build tools, Windows SDK, and a Python installation that includes `python3.lib`.
See the [source build prerequisites](../../docs/src/installation.md#build-from-source).

Create a virtual environment:

```sh
git clone https://github.com/1-3-7/disrobe
cd disrobe/bindings/python
python -m venv .venv
```

Activate it on Linux or macOS:

```sh
source .venv/bin/activate
```

On Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Then build and install the extension into that environment:

```sh
python -m pip install "maturin>=1.5,<2.0"
maturin develop --release
python -c "import disrobe; print(disrobe.__version__)"
```

To build a wheel instead:

```sh
maturin build --release --out dist
python -m pip install --no-index --find-links dist disrobe
```

## Run automatic recovery

Pass the input bytes and their path to `auto`. The path helps passes find
companion files. The result contains the chain report; this call does not write
the CLI's stage directories. `max_depth` accepts values from 1 through 16.

```python
from __future__ import annotations

from pathlib import Path

import disrobe

input_path: Path = Path("application.exe")
input_bytes: bytes = input_path.read_bytes()

report: disrobe.ChainReport = disrobe.auto(
    input_bytes,
    max_depth=8,
    path_hint=str(input_path),
)

print(report.to_json())
```

## Recover Python source

Read a `.pyc` file, then inspect its source and recovery status. A report can
contain partial output or a fallback reason. Source recovery does not execute
the recovered program.

```python
from __future__ import annotations

from pathlib import Path

import disrobe

pyc_bytes: bytes = Path("module.pyc").read_bytes()
report: disrobe.PyDecompileReport = disrobe.py_decompile(pyc_bytes)
source: str | None = report.source

if source is not None:
    print(source)

print(report.recovered_directly, report.fallback_reason)
```

For a recompilation comparison, pass `roundtrip=True` and inspect
`report.roundtrip_status` and `report.roundtrip_detail`. That option invokes a
matching Python interpreter to compile the recovered source; it does not run
the recovered program.

## Inspect a PyArmor payload

`pyarmor_unpack` accepts the binary payload extracted from a protected wrapper.
Its report describes the static unpack result; it does not return the recovered
plaintext itself. This binding has no runtime-module argument, so v8/v9 payloads
return detection metadata without decrypted plaintext. Use `pyarmor_detect` to
inspect wrapper source text directly.

```python
from __future__ import annotations

from pathlib import Path

import disrobe

payload: bytes = Path("payload.bin").read_bytes()
report: disrobe.PyarmorUnpack = disrobe.pyarmor_unpack(payload)

print(report.status)
print(report.plaintext_len, report.plaintext_blake3_hex)
```

## Inspect JavaScript

Detect an obfuscator family from UTF-8 source:

```python
from __future__ import annotations

from pathlib import Path

import disrobe

source: str = Path("main.js").read_text(encoding="utf-8")
detection: disrobe.JsDetection = disrobe.js_detect(source)

print(detection.family, detection.confidence)
```

Recover the module structure of a supported bundle:

```python
from __future__ import annotations

from pathlib import Path

import disrobe

source: str = Path("bundle.js").read_text(encoding="utf-8")
report: disrobe.JsUnbundle = disrobe.js_unbundle(source)

print(report.bundler, report.module_count)
print(report.to_json())
```

## Function surface

| Category | Functions |
|---|---|
| Automatic recovery | `auto` |
| Generic dispatch | `decompile`, `disasm`, `parse`, `compile` |
| Custom passes and consumers | `register_pass`, `register_consumer`, `registered_passes`, `registered_consumers`, `unregister`, `run_pass`, `run_chain`, `emit` |
| Analysis | `strings_extract`, `ioc_extract`, `behavior_analyze`, `identify`, `secret_scan`, `capabilities`, `yara_parse`, `yara_generate` |
| Extraction and containers | `extract`, `extract_recursive`, `byte_coverage`, `container_detect`, `container_members` |
| Native code | `native_format`, `native_detect`, `native_symbols`, `native_disasm`, `native_callgraph`, `native_imports_dot`, `native_entropy`, `native_sbom`, `native_fingerprint`, `native_signatures`, `native_sigmaker`, `native_diff`, `native_match`, `native_patch`, `native_deobfuscate`, `native_probe_backends` |
| IR queries | `query_functions`, `query_calls_to`, `query_xrefs_to`, `query_string_decoders`, `query_complexity_over`, `query_capability_sites`, `query_call_graph` |
| Python | `py_decompile`, `py_disasm`, `py_deob`, `py_deob_detect`, `py_deob_list_passes`, `py_deob_detect_pass` |
| PyArmor | `pyarmor_detect`, `pyarmor_unpack`, `pyarmor_classify` |
| PyInstaller | `pyinstaller_extract`, `pyinstaller_entry_bytes` |
| Nuitka | `nuitka_detect`, `nuitka_extract` |
| Hermes | `hermes_disasm`, `hermes_lift`, `hermes_info` |
| Flutter | `flutter_engine_symbols` |
| Mach-O and Swift | `macho_dump`, `swift_analyze` |
| JVM and Android | `jvm_parse_class`, `jvm_parse_dex`, `jvm_decompile_class`, `jvm_decompile_dex`, `jvm_detect`, `jvm_backends`, `jvm_jni_link`, `apk_resources` |
| .NET | `dotnet_parse_pe`, `dotnet_parse_metadata`, `dotnet_detect`, `dotnet_analyze`, `dotnet_decompile`, `dotnet_recover_decoders`, `dotnet_native_aot`, `dotnet_backends` |
| WebAssembly | `wasm_analyze`, `wasm_detect`, `wasm_lift` |
| JavaScript | `js_detect`, `js_unminify`, `js_unbundle` |
| Lua | `lua_detect`, `lua_decompile`, `lua_deobfuscate` |
| Go | `go_analyze`, `go_symbols`, `go_pclntab`, `go_garble` |
| Ruby | `ruby_detect`, `ruby_decompile` |
| PHP | `php_detect`, `php_scan`, `php_decode` |
| Shell | `batch_deobfuscate`, `powershell_detect`, `powershell_deobfuscate` |
| Pickle | `pickle_disasm`, `pickle_decompile`, `pickle_safety`, `pickle_trace`, `pickle_polyglot`, `pickle_ml_detect` |
| Envelopes | `envelope_create`, `envelope_verify` |
| Metadata renders | `agents_md`, `skill_md`, `provenance` |

Recovery failures raise `disrobe.DisrobeError`. Generic dispatch raises its
`disrobe.UnsupportedLanguage` subclass when the requested language has no
implementation. Invalid Python argument types can raise standard Python
exceptions.

Use `help(disrobe)` for the installed API. The [Python bindings chapter](../../docs/src/python-bindings.md)
describes report attributes, serialization, and per-function examples.
