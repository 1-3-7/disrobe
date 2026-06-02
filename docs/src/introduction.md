# disrobe

> Strip the obfuscation, read the source.

**disrobe** is a deterministic, multi-language deobfuscator and decompiler suite that ships as a single Rust binary. One tool covers the bytecode, packers, freezers, and protectors stacked across the modern software supply chain: Python, JavaScript/TypeScript, WebAssembly, JVM and Android, .NET, native PE/ELF/Mach-O, Go, Lua, PHP, Ruby, Erlang/Elixir (BEAM), Swift/Objective-C, ActionScript 3, React Native Hermes, Flutter Dart AOT, and the 22 native packers commonly layered on top of them.

It is built for forensic and recovery work where reproducibility matters:

- **Deterministic.** No model anywhere in the decompile path. The same input produces byte-identical output on every machine, every run. That is what makes disrobe output usable as evidence and as a diff baseline.
- **Single static binary.** No JVM, no Python runtime, no Docker image required to run the core. Builds from one `cargo build --release`. Drops into CI headlessly.
- **Content-addressed.** Every recovered artifact persists as a `.dr` envelope: an rkyv hot payload plus a postcard cold sidecar, rooted by a BLAKE3 hash. Cache hits are byte-identical and chains compose offline.
- **Honest.** Every Python decompile is recompiled on the matching interpreter and compared opcode-for-opcode. Recovery that is not perfect is labelled `SEMANTIC`, `PARTIAL`, or `SKELETON` rather than presented as ground truth. Commercial-tier packers that disrobe cannot fully unpack are reported as detect-only by design, never faked.

## Who this is for

- **Malware analysts and incident responders** who receive a packed, frozen, or obfuscated sample and need to read what it does, without executing it.
- **Security researchers** auditing a closed binary for interoperability or vulnerability research.
- **Developers** recovering their own lost source from a shipped `.pyc`, `.jar`, `.dll`, or bundled `.js`.
- **Coding agents.** Every pass can emit a structured metadata sidecar (`--llm`) carrying the call graph, type signatures, control-flow shape, capability surface, and decompile provenance, so an LLM can reason about recovered code without re-deriving its structure.

## What makes it different

disrobe is the only single binary shipping passes for every ecosystem above. Where best-in-class FOSS already exists (CFR, Vineflower, jadx, ILSpy, JPEXS, unluac, hermes-dec, Ghidra), disrobe wraps it headlessly behind a unified CLI and adds chain auto-detection, deterministic `.dr` envelopes, and round-trip verification. Where the field is thin or non-existent (PyArmor v9-pro, the native packer tier, Hermes against a live bundle, Flutter Dart AOT, MicroPython `.mpy`, PEP 750 t-strings), disrobe is the canonical tool. Where the field is dominant (Ghidra/IDA/Binary Ninja for native decompilation), disrobe is the unpack, symbol-recovery, and chain-detect layer that feeds them cleaner input.

## How to read these docs

- New here? Start with [Installation](./installation.md) and [Quickstart](./quickstart.md).
- Want to understand the design? Read the [Architecture overview](./architecture.md), then [the five-rung IR ladder](./ir-ladder.md).
- Looking for a specific language? Jump to its [language guide](./languages/python.md).
- Need an exact command or flag? See the [CLI command reference](./cli/reference.md).
- Running disrobe against untrusted samples? Read [Forensics and malware-safety posture](./forensics-safety.md) first.
