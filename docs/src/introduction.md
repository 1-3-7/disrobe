# `disrobe`: a universal decompiler, deobfuscator, and unpacker

![disrobe](./assets/social-card.svg)

> One tool to decompile, deobfuscate, and unpack almost anything, deterministically, in a single Rust binary.

`disrobe` is a universal multi-language decompiler and deobfuscator. It decompiles Python `.pyc` bytecode, unpacks PyArmor and PyInstaller, reads Nuitka-compiled binaries, decompiles WebAssembly, deobfuscates JavaScript, decompiles .NET / CIL and JVM / Java, recovers Android DEX, and unwraps native PE / ELF / Mach-O packers, all from one static binary built for malware analysis and reverse engineering.

[![disrobe demo](./demo/disrobe-demo.svg)](https://github.com/1-3-7/disrobe/blob/main/docs/demo/disrobe.cast)

> **Try it in your browser: [the `disrobe` playground](https://1-3-7.github.io/disrobe/playground/).** Decompile a `.pyc`, scan a pickle for malicious reduce callables, and summarize a `.wasm` module, all client-side, with the core passes compiled to WebAssembly. Nothing is uploaded.

`disrobe` reverses the bytecode, packers, freezers, and protectors layered onto compiled and frozen software across 20+ ecosystems: Python, JavaScript/TypeScript, WebAssembly, JVM and Android, .NET, native PE/ELF/Mach-O, Go, Lua, PHP, Ruby, Erlang/Elixir (BEAM), Swift/Objective-C, ActionScript 3, React Native Hermes, Flutter Dart AOT, and the native packer tier layered on top of them (UPX, MPRESS, NSPack, FSG, kkrunchy, MEW, ASPack, PECompact, Petite, Yoda's Crypter). It ships as a single static Rust binary.

Built for forensic and recovery work where reproducibility matters:

- No model runs anywhere in the decompile path. The same input produces byte-identical output on every machine and every run, so a result serves as evidence and as a diff baseline.
- The core runs as one static binary. It needs no JVM, no Python runtime, and no Docker image. It builds from a single `cargo build --release` and drops into CI headlessly.
- Every recovered artifact persists as a content-addressed `.dr` envelope: an rkyv hot payload plus a postcard cold sidecar, rooted by a BLAKE3 hash. Cache hits are byte-identical, and chains compose offline.
- Every Python decompile is recompiled on the matching interpreter and compared opcode-for-opcode: <!-- m:py_stdlib_full_pct -->95.09%<!-- /m --> per-code-object equivalence on the full CPython 3.14 stdlib (<!-- m:py_stdlib_full_count -->17378 of 18276<!-- /m -->), plus <!-- m:py_stdlib_pinned_pct -->96.6%<!-- /m --> on the pinned 200-module corpus (<!-- m:py_stdlib_pinned_count -->6072 of 6286<!-- /m -->). Recovery that falls short is labelled `SEMANTIC`, `PARTIAL`, or `SKELETON` rather than presented as ground truth. Commercial-tier packers that `disrobe` cannot fully unpack are reported as detect-only by design, never faked.

## Who this is for

- Malware analysts and incident responders who receive a packed, frozen, or obfuscated sample and need to read what it does, without executing it.
- Security researchers auditing a closed binary for interoperability or vulnerability research.
- Developers recovering their own lost source from a shipped `.pyc`, `.jar`, `.dll`, or bundled `.js`.
- Review tooling. Every pass can emit a structured metadata sidecar (`--metadata-pack-4`, with `--llm` kept as a compatibility alias) carrying the call graph, type signatures, control-flow shape, capability surface, and decompile provenance. The sidecar is deterministic data for downstream tooling, not a model-backed decompiler.

## Where it sits against existing tools

`disrobe` ships passes for every ecosystem above from a single binary. Where mature FOSS already exists (CFR, Vineflower, jadx, ILSpy, JPEXS, unluac, hermes-dec, Ghidra), `disrobe` wraps it headlessly behind a unified CLI and adds chain auto-detection, deterministic `.dr` envelopes, and round-trip verification. Where FOSS coverage is thin (PyArmor v9-pro, the native packer tier, Hermes against a live bundle, Flutter Dart AOT, MicroPython `.mpy`, PEP 750 t-strings), it is among the few tools handling these statically and offline. Where the field is dominant (Ghidra/IDA/Binary Ninja for native decompilation), `disrobe` is the unpack, symbol-recovery, and chain-detect layer that feeds them cleaner input.

## Measured recovery

Every figure below is produced by a committed test gate or a local measurement harness graded against an independent oracle, never the tool's own output. The full per-value sourcing lives in [`xtask/data/recovery.json`](https://github.com/1-3-7/disrobe/blob/main/xtask/data/recovery.json).

![Measured recovery by ecosystem](./assets/recovery.svg)

| Ecosystem | Measured | Oracle |
|---|---|---|
| Python bytecode | <!-- m:py_stdlib_full_pct -->95.09%<!-- /m --> per-code-object equivalence on the full CPython 3.14 stdlib (<!-- m:py_stdlib_full_count -->17378 of 18276<!-- /m -->); <!-- m:py_stdlib_pinned_pct -->96.6%<!-- /m --> on the pinned 200-module corpus (<!-- m:py_stdlib_pinned_count -->6072 of 6286<!-- /m -->). Whole-module exact, where a module counts only if all of its code objects pass: 54.5% on the pinned corpus | recompile on CPython 3.14.5, opcode diff |
| CPython legacy 1.0-3.7 | <!-- m:py_legacy_count -->150 of 191<!-- /m --> proven-correct (CI floor); <!-- m:py_legacy_local_count -->166 of 191<!-- /m --> measured locally | recompile-equivalence or structural token-match |
| WebAssembly | 133 of 133 corpus functions op-covered across the 38 parseable modules; 57 of 57 execution-eligible functions equivalent | execution differential under wasmtime |
| JVM classfile | <!-- m:jvm_per_method_count -->131 of 131<!-- /m --> methods recompile error-free | real `javac` |
| Android (Dalvik) | <!-- m:dalvik_verifier_pct -->99%<!-- /m --> of the committed dex corpus passes the JVM verifier (<!-- m:dalvik_verifier_count -->102 of 103<!-- /m --> classes; the 103rd is link-skipped before verification, so the gate counts every one of the 102 verifiable classes clean) | `-Xverify:all` over assembled jar |
| Ruby YARV | greeter <!-- m:ruby_greeter_pct -->100%<!-- /m -->, megafile <!-- m:ruby_megafile_pct -->98%<!-- /m --> opcode-multiset equivalence | recompile on MRI |
| PyArmor | <!-- m:pyarmor_samples -->72<!-- /m --> of 72 real-corpus samples recovered | plaintext-absent oracle |
| Containers | <!-- m:containers_formats -->100<!-- /m --> formats detected, <!-- m:containers_formats -->100<!-- /m --> extracted in-tree | per-format byte length |

The numbers that are not perfect are labelled `SEMANTIC`, `PARTIAL`, or `SKELETON`, and the information-theoretic walls (native-virtualized code, runtime-only keys, RSA-wrapped capsule keys) are reported as detect-only by design.

## Refusal is a result

`disrobe` refuses to emit a recovery it cannot justify from the input. A refusal names its reason and is a normal, expected outcome, not a failure of the run.

The rule behind it: a wrong recovery costs more than no recovery. A reader who receives output assumes it describes the input, so output that merely looks plausible is worse than a refusal that says what was missing. Two consequences follow, and both are deliberate.

Evidence that is only probable does not become a result. Where several readings of the same bytes are equally consistent with the input, `disrobe` reports the ambiguity instead of choosing the likeliest one. A native function compiled to a single return instruction, for example, cannot be distinguished from several different source signatures on its own bytes, so it is refused unless a caller in the same object proves which one applies.

A refusal is scoped to the evidence, not to the problem. "Not recoverable from this input" is a claim about the bytes supplied; a wider input set can reopen it. Only a limit that survives that distinction, such as a key that exists solely at run time, is reported as a wall.

## Where to start

- First run: [Installation](./installation.md), then [Quickstart](./quickstart.md).
- The design: [Architecture overview](./architecture.md), then [the five-rung IR ladder](./ir-ladder.md).
- One language: its [language guide](./languages/python.md).
- The full family list: the [supported families catalog](./catalog.md), or `disrobe catalog [ecosystem]`.
- Triage of stripped code or recovered source: [queryable IR and capabilities](./query.md) and [recon, prowl, and indicators](./frisk.md).
- Embedding: [Use it as a library](./library.md), or [the browser playground](./playground.md) first.
- An exact command or flag: the [CLI command reference](./cli/reference.md).
- Untrusted samples: [Forensics and malware-safety posture](./forensics-safety.md), before anything else.
