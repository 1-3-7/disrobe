# Use it as a library

Use Disrobe through its Rust crates, Python bindings, or service protocols. The CLI and bindings share the same Rust implementations.

## Rust

Ecosystem recovery code is split across dedicated crates over shared artifact and IR types, so a library consumer can select only the surfaces it needs. A crate may expose multiple direct operations or chain passes. The pass registry and chain state machine live in `disrobe-core`; `disrobe-passes` assembles the feature-selected registry used by `disrobe auto`.

| Crate | What you get |
|---|---|
| `disrobe-core` | Shared types: `Artifact`, `Rung`, confidence tiers, error codes, the chain registry and state machine, the `Pass`/`Detector` traits, and the obfuscator-catalog traits. |
| `disrobe-ir` | The five-rung IR ladder, the `.dr` envelope (rkyv hot payload + postcard cold sidecar + BLAKE3 root), and the transcode registry. |
| `disrobe-nir`, `disrobe-nir-lift` | Normalized MIR and bytecode front ends for AVM2, BEAM, CIL, Dalvik, JVM, Lua, Python, WebAssembly, and YARV. |
| `disrobe-binfmt` | Container detection, in-tree format extractors, recursive carving, and shared extraction quotas. |
| `disrobe-passes` | The single construction site for a feature-selected `PassRegistry`. |
| `disrobe-prowl` | Typed URL and IOC harvest reports, source filters, bounded async provider fan-out, and API-key resolution for the `prowl` CLI. |
| `disrobe-pass-py-decompile`, `disrobe-pass-jvm`, `disrobe-pass-native`, `disrobe-pass-dotnet`, ... | One crate per ecosystem, each exposing a typed `Pass` plus direct entry points (for example the Python decompiler's `PY_DECOMPILE_PASS` and `roundtrip_native`). |
| `disrobe-pass-webview` | Static Electron ASAR and embedded Tauri/Wails frontend recovery with typed reports and extraction quotas. |
| `disrobe-query`, `disrobe-capabilities` | The queryable-IR layer and the ATT&CK/MBC rule engine over the disassembled native code. |
| `disrobe-taint` | Source-to-sink flow analysis over normalized native, WebAssembly, JVM, Dalvik, and `.dr` inputs. |

Add the crates you want to a workspace member or an external project that pins the published versions:

```toml
[dependencies]
disrobe-core = "0.10"
disrobe-ir = "0.10"
disrobe-pass-py-decompile = "0.10"
```

For a runnable example, inspect a WebAssembly module and emit WAT directly through the Rust API:

```sh
cargo run --locked -p disrobe-pass-wasm-deob --example inspect_module -- playground/public/samples/add.wasm
```

The [example source](https://github.com/1-3-7/disrobe/blob/main/crates/disrobe-pass-wasm-deob/examples/inspect_module.rs) reads at most 16 MiB, calls `analyze_module` and `lift_module_faithful_wat`, then prints the function inventory and recovered text. It does not execute the module.

For the bundled `add.wasm`, it reports one function, no imports, and the `add` export.
The [captured output](https://github.com/1-3-7/disrobe/blob/main/docs/demo/rust-library.json)
includes the emitted WAT and hashes of the fixture, example source, and executable.

Chain passes implement the shared `Pass` trait. Each exposes a `Detector` and a `run` method that transforms an `Artifact` into a new artifact. Enable the pass crate's `chain` feature when using this interface.

The Python decompiler exposes `roundtrip_native`, which recompiles recovered source on the matching interpreter and returns a `RoundtripOutcome` with a `PERFECT`, `SEMANTIC` or `CODE_DIFF` verdict. Its Rust comparison retains operands and jump targets. The published stdlib measurement uses separate [normalized opcode-structure rules](./languages/python.md#measured-opcode-structure).

Because every chain pass speaks the same `Artifact` dialect, `PassRegistry` can re-detect the current bytes after each stage and select the highest-confidence, highest-precedence verdict without a per-pair compatibility table. The registry contains only the passes compiled and registered by the caller. The standard CLI uses `disrobe-passes` as its assembly point; `disrobe passes` shows what that build exposes to `auto`. The shape of the `Pass` trait and the selection mechanism is in [Passes and pass selection](./passes.md#pass-selection).

## Python

`import disrobe` loads a pyo3 `abi3` module for Python 3.9+, built with `maturin` from `crates/disrobe-python`. It includes a `.pyi` stub and `py.typed` marker. Analysis functions accept bytes and return typed reports. Most analysis functions leave file I/O to the caller. Container extraction and an explicitly selected Flutter engine-symbol cache write to caller-supplied directories.

```python
from __future__ import annotations

from pathlib import Path

import disrobe
from disrobe import (
    CanonicalSource,
    Capabilities,
    ChainReport,
    CodeObject,
    Instruction,
    Symbol,
)

chain: ChainReport = disrobe.auto(Path("sample.bin").read_bytes())

print(chain.to_json())

recovered: CanonicalSource = disrobe.decompile(
    "python-bytecode", Path("module.pyc").read_bytes()
)
source: str | None = recovered.source

caps: Capabilities = disrobe.capabilities(Path("packed.exe").read_bytes())

print(caps.format, caps.match_count)

obj: CodeObject = CodeObject.from_dr(Path("module.dr").read_bytes())

obj.add_symbol(Symbol(0x401000, "decrypt_config"))
obj.add_instruction(Instruction(0x401000, "xor", ["eax", "eax"]))

patched_dr: bytes = obj.to_dr()
```

The surface spans `auto`, typed entry points for every major ecosystem, a generic `disasm`/`parse`/`compile`/`decompile` dispatch, a mutable `CodeObject` you load from a `.dr` envelope, edit, and re-serialize, and a `register_pass`/`register_consumer` registry for your own stages. The full function list and conventions are in the [Python-bindings reference](./python-bindings.md).

## Daemon

`disrobe serve` exposes HTTP and gRPC endpoints. `disrobe serve --stdio` provides LSP over standard input and output, and `disrobe serve --mcp` exposes MCP tools. Their operation sets differ; see the [service reference](./cli/serve.md) and [MCP tool list](./integrations/mcp.md).
