# Use it as a library

`disrobe` embeds as well as it runs from a shell. The CLI integrates the same crates exposed to library consumers. There are three primary entry points: the Rust crates, the Python bindings, and the daemon.

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

Each pass implements the shared `Pass` trait: it exposes a `Detector` that scores how confidently it recognizes an input, and a `run` method that takes an `Artifact` at one rung and returns an `Artifact` one or more rungs higher. Driving a pass directly looks like this (illustrative):

```rust,ignore
use disrobe_core::pass::Pass;
use disrobe_core::{Artifact, Rung};
use disrobe_pass_py_decompile::chain_detector::PY_DECOMPILE_PASS;

fn recover(pyc: Vec<u8>, root: [u8; 32]) -> disrobe_core::Result<Artifact> {
    let input: Artifact = Artifact::new(Rung::Raw, pyc, root);
    let recovered: Artifact = PY_DECOMPILE_PASS.run(&input)?;
    let surface: &[u8] = recovered.envelope.as_slice();
    println!("rung={:?} bytes={}", recovered.rung, surface.len());
    Ok(recovered)
}
```

The Python decompiler additionally exposes `roundtrip_native`, which recompiles recovered source on the matching interpreter and returns a `RoundtripOutcome` carrying the `PERFECT`/`SEMANTIC`/`CODE_DIFF` verdict, so the same recompile-equivalence check the CI gate runs is available in-process.

Because every chain pass speaks the same `Artifact` dialect, `PassRegistry` can re-detect the current bytes after each stage and select the highest-confidence, highest-precedence verdict without a per-pair compatibility table. The registry contains only the passes compiled and registered by the caller. The standard CLI uses `disrobe-passes` as its assembly point; `disrobe passes` shows what that build exposes to `auto`. The shape of the `Pass` trait and the selection mechanism is in [Passes and pass selection](./passes.md#pass-selection).

## Python

`import disrobe` is a pyo3 `abi3` module (Python 3.9+, shipping a full `.pyi` and `py.typed`), built with `maturin` from `crates/disrobe-python`. Bytes in, concrete typed report objects out, deterministic, and the bindings never touch the filesystem so the caller owns all I/O.

```python
import disrobe
from disrobe import Capabilities, CanonicalSource, ChainReport, CodeObject, Instruction, Symbol

with open("sample.bin", "rb") as f:
    chain: ChainReport = disrobe.auto(f.read())
print(chain.spec, chain.pass_count, chain.terminated)

with open("module.pyc", "rb") as f:
    recovered: CanonicalSource = disrobe.decompile("python-bytecode", f.read())
source: str | None = recovered.source

with open("packed.exe", "rb") as f:
    caps: Capabilities = disrobe.capabilities(f.read())
print(caps.format, caps.match_count)

with open("module.dr", "rb") as f:
    obj: CodeObject = CodeObject.from_dr(f.read())
obj.add_symbol(Symbol(0x401000, "decrypt_config"))
obj.add_instruction(Instruction(0x401000, "xor", ["eax", "eax"]))
patched_dr: bytes = obj.to_dr()
```

The surface spans `auto`, typed entry points for every major ecosystem, a generic `disasm`/`parse`/`compile`/`decompile` dispatch, a mutable `CodeObject` you load from a `.dr` envelope, edit, and re-serialize, and a `register_pass`/`register_consumer` registry for your own stages. The full function list and conventions are in the [Python-bindings reference](./python-bindings.md).

## Daemon

`disrobe serve` speaks HTTP, gRPC, and LSP, taking base64 bytes and returning structured JSON, so any language can drive it over a socket. `disrobe serve --mcp` exposes the same operations as Model Context Protocol tools for automation clients. The wire surface is documented in [The daemon](./cli/serve.md).
