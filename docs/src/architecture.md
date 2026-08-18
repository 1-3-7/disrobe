# Architecture overview

`disrobe` is a workspace of focused Rust crates orchestrated by one CLI. Every recovery flows through the same shape: bytes in, a chain of **passes** that each transform the artifact up the **IR ladder**, an optional **`.dr` envelope** for content-addressed caching, and a final emit.

For the full design rationale, including the determinism argument and the oracle-grading methodology, read the [architecture whitepaper](./architecture/whitepaper.md).

## The shape of a recovery

```text
                   ┌──────────────────────────────────────────────┐
   input bytes ──> │  detect  ──>  pass 1  ──>  pass 2  ──>  ...  │ ──> recovered artifact
                   └──────────────────────────────────────────────┘
                          │           │            │
                          │           │            └─ each pass: raw -> disasm -> mir -> hir -> surface
                          │           └─ detector confidence + precedence pick what runs next
                          └─ chain runner records chain.json + stage mirrors + recovery.json
```

## Crate map

The workspace splits into shared cores and dedicated ecosystem or recovery-surface crates:

| Crate | Role |
|---|---|
| `disrobe-core` | Shared artifacts, error codes (`DR-<DOMAIN>-<NNNN>`), confidence tiers, the `Pass` and `Detector` traits, pass selection, and the chain state machine. |
| `disrobe-prowl` | Async URL and IOC harvester over public archives and threat-intel feeds, with bounded paging, per-host rate limits, key resolution, and typed reports. |
| `disrobe-ir` | The five-rung IR ladder, the `.dr` envelope (rkyv hot + postcard cold + BLAKE3 root), transcoders, capability descriptors. |
| `disrobe-nir`, `disrobe-nir-lift` | Normalized MIR plus bytecode front ends for AVM2, BEAM, CIL, Dalvik, JVM, Lua, Python, WebAssembly, and YARV. |
| `disrobe-binfmt` | Container, archive, filesystem, and firmware layer (<!-- m:containers_formats -->101<!-- /m --> formats detected, each with an in-tree extractor and <!-- roster-breadth:containers-exercised -->39<!-- /roster-breadth --> of them reached by a committed input, plus recursive carving) with shared path-safety and decompression-quota machinery. |
| `disrobe-passes` | Single assembly point for the feature-selected auto-chain registry. The standard CLI enables a specific subset; `disrobe passes` prints the resulting IDs. |
| `disrobe-llm-metadata` | The `--llm` sidecar: 18 categories, 4 packs, `AGENTS.md` / `SKILL.md` brief generation. |
| `disrobe-mcp` | The rmcp Model Context Protocol companion wired to `disrobe serve --mcp`. |
| `disrobe-py-marshal` | CPython marshal reader: code objects across 1.0-3.15. |
| `disrobe-pass-*` | One crate per ecosystem or recovery surface, including Python, JavaScript, WebAssembly, JVM, .NET, native, Go, Lua, PHP, Ruby, BEAM, Swift/Objective-C, AS3, mobile, shell, and webview desktop assets. The native pass adds the iced-backed disassembler, symbol-independent function discovery, call graph and basic-block CFG, instruction re-encode/relocate, C++ RTTI/vtable recovery, and emulation-driven string recovery. |
| `disrobe-query` | Queryable-IR layer over the disassembled native code: functions, calls-to, xrefs, string-decoders, complexity, capability sites, behind `disrobe query`. |
| `disrobe-capabilities` | Capability rule engine over the queryable IR, mapping matched behaviors to MITRE ATT&CK and MBC, behind `disrobe capabilities`. |
| `disrobe-taint` | Source-to-sink data-flow analysis over normalized native, WebAssembly, JVM, Dalvik, and `.dr` inputs, behind `disrobe taint`. |
| `disrobe-cli` | The `disrobe` binary: argument parsing, direct command handlers, output formats, chain integration, and daemon protocols. |
| `disrobe-validator` | Walks a corpus and validates every fixture round-trips, used in CI. |

## The `Pass` trait

Every chain pass implements one trait (`Pass` in `disrobe-core`, re-exported as `chain::detector::Pass`): it exposes a `Detector` that scores how confidently it recognizes an input, plus a `run` method that takes an `Artifact` at one rung and returns an `Artifact` one or more rungs higher. Because every chain pass speaks the same detector interface, the chain runner needs no per-pair compatibility table: it re-detects the current bytes after every stage and picks whichever registered pass returns the highest-confidence, highest-precedence verdict. This is what lets `PyInstaller -> PyArmor -> .pyc decompile` work as a single `disrobe auto` invocation rather than three hand-wired steps.

The CLI also has a standardized emit vocabulary, but it is not part of the `Pass` trait and support varies by command. A command wired to the emit helper writes an `applicable: false` stub when a requested kind does not apply. `auto` accepts only the `recovery` emit. See [Standardized emits](./passes.md#standardized-emits).

## The four pillars

1. [The five-rung IR ladder](./ir-ladder.md): the common intermediate representation every artifact climbs.
2. [Passes and pass selection](./passes.md): what each pass registers and how the chain runner picks between them.
3. [The chain runner](./chain.md): auto-detection, stage mirrors, depth and cycle caps.
4. [The `.dr` envelope](./envelope.md): the content-addressed wire format that makes caching deterministic.

## Determinism is a design constraint, not a feature

The recovery architecture is designed for reproducible output. No model runs in the decompile path, and recovery output does not depend on randomness. Opt-in redaction uses the first 96 bits of the value's unsalted SHA-256 digest, so the same value receives the same sentinel across runs. Values shorter than 16 characters reveal no source characters. Longer values reveal only the first two and last two characters. Timing tokens are scrubbed from golden outputs so that two runs hash identically. The `.dr` envelope is content-addressed with BLAKE3 rather than timestamp-addressed, so a cache hit identifies the same bytes. This makes `disrobe` output usable as a forensic baseline and as a `disrobe diff` input across versions.

The committed cross-platform gate exercises three real fixtures. Each of the `test` job's Linux, macOS, and Windows legs runs the CLI against those fixtures, and the downstream `determinism-cross-platform` job hashes the recovered output with BLAKE3 and fails if the operating systems disagree. A companion check runs the same fixtures through the batch path at `--jobs 1` and `--jobs 4`. These checks establish determinism for that population; they do not turn three fixtures into a claim about every input. See `crates/disrobe-cli/tests/determinism_cross_platform.rs` and the `determinism-cross-platform` job in `.github/workflows/ci.yml`.
