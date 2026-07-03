# Use it as a library

**disrobe** is built to be embedded, not just run from a shell. The CLI is a thin layer over the same crates, so a TUI, an IDE plugin, a web service, or a batch engine can drive the full pass set directly. There are three ways in: the Rust crates, the Python bindings, and the daemon.

## Rust

Every pass is its own crate over the shared `disrobe-core` and `disrobe-ir` types, so you depend only on the ones you need. The chain runner that backs `disrobe auto` lives in `disrobe-binfmt`.

| Crate | What you get |
|---|---|
| `disrobe-core` | Shared types: the `Artifact` envelope, `Rung`, confidence tiers, error codes, the chain `Pass`/`Detector` traits, and the obfuscator-catalog traits. |
| `disrobe-ir` | The five-rung IR ladder, the `.dr` envelope (rkyv hot payload + postcard cold sidecar + BLAKE3 root), and the transcode registry. |
| `disrobe-binfmt` | Container detection, the 98-format extractors, and the chain runner. |
| `disrobe-prowl` | Typed URL and IOC harvest reports, source filters, bounded async provider fan-out, and API-key resolution for the `prowl` CLI. |
| `disrobe-pass-py-decompile`, `disrobe-pass-jvm`, `disrobe-pass-native`, `disrobe-pass-dotnet`, ... | One crate per ecosystem, each exposing a typed `Pass` plus direct entry points (for example the Python decompiler's `DecompilePass` and `roundtrip_native`). |
| `disrobe-query`, `disrobe-capabilities` | The queryable-IR layer and the ATT&CK/MBC rule engine over the disassembled native code. |

Add the crates you want to a workspace member or an external project that pins the published versions:

```toml
[dependencies]
disrobe-core = "0.10"
disrobe-ir = "0.10"
disrobe-pass-py-decompile = "0.10"
```

Each pass implements the shared `Pass` trait: it takes an `Artifact` at one rung and returns an `Artifact` one or more rungs higher, declaring the capabilities it requires and produces. Driving a pass directly looks like this (illustrative):

```rust,ignore
use disrobe_core::pass::Pass;
use disrobe_core::{Artifact, Rung};
use disrobe_pass_py_decompile::DecompilePass;

fn recover(pyc: Vec<u8>, root: [u8; 32]) -> disrobe_core::Result<Artifact> {
    let input: Artifact = Artifact::new(Rung::Raw, pyc, root);
    let pass: DecompilePass = DecompilePass::new();
    let recovered: Artifact = pass.run(&input)?;
    let surface: &[u8] = recovered.envelope.as_slice();
    println!("rung={:?} bytes={}", recovered.rung, surface.len());
    Ok(recovered)
}
```

The Python decompiler additionally exposes `roundtrip_native`, which recompiles recovered source on the matching interpreter and returns a `RoundtripOutcome` carrying the `PERFECT`/`SEMANTIC`/`CODE_DIFF` verdict, so the same recompile-equivalence check the CI gate runs is available in-process.

Because every pass speaks the same `Artifact` dialect, the `disrobe-binfmt` chain runner composes any pass with any other as long as the capability resolver is satisfied. That is what lets `PyInstaller -> PyArmor -> .pyc decompile` run as one call rather than three hand-wired steps. The shape of the `Pass` trait and the resolver is in [Passes and the capability model](./passes.md).

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
