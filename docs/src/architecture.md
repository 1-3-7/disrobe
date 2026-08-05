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

The workspace splits into a small set of shared cores and one crate per ecosystem pass:

| Crate | Role |
|---|---|
| `disrobe-core` | Shared types: error codes (`DR-<DOMAIN>-<NNNN>`), progress, confidence tiers, secret/credential scanning, cyclomatic metrics. |
| `disrobe-prowl` | Async URL and IOC harvester over public archives and threat-intel feeds, with bounded paging, per-host rate limits, key resolution, and typed reports. |
| `disrobe-ir` | The five-rung IR ladder, the `.dr` envelope (rkyv hot + postcard cold + BLAKE3 root), transcoders, capability descriptors. |
| `disrobe-binfmt` | Container, archive, filesystem, and firmware layer (<!-- m:containers_formats -->100<!-- /m --> formats detected, each with an in-tree extractor and <!-- roster-breadth:containers-exercised -->34<!-- /roster-breadth --> of them reached by a committed input, plus a recursive carve-everything engine) with shared zip-slip and decompression-bomb quota machinery. |
| `disrobe-llm-metadata` | The `--llm` sidecar: 18 categories, 4 packs, `AGENTS.md` / `SKILL.md` brief generation. |
| `disrobe-mcp` | The rmcp Model Context Protocol companion wired to `disrobe serve --mcp`. |
| `disrobe-py-marshal` | CPython marshal reader: code objects across 1.0-3.15. |
| `disrobe-pass-*` | One crate per ecosystem (py-decompile, py-disasm, py-deob, pyarmor, pyinstaller, pyfreeze, nuitka, js-deob, wasm-deob, jvm, dotnet, native, nativelang, go, lua, php, ruby, beam, pickle, swift-objc, as3, mobile, shell, scriptlang, sourcedefender). The native pass adds the iced-backed disassembler, symbol-independent function discovery, call graph and basic-block CFG, instruction re-encode/relocate, C++ RTTI/vtable recovery, and emulation-driven string recovery. |
| `disrobe-query` | Queryable-IR layer over the disassembled native code: functions, calls-to, xrefs, string-decoders, complexity, capability sites, behind `disrobe query`. |
| `disrobe-capabilities` | Capability rule engine over the queryable IR, mapping matched behaviors to MITRE ATT&CK and MBC, behind `disrobe capabilities`. |
| `disrobe-cli` | The `disrobe` binary: argument parsing, output formats, the chain runner, the daemon. |
| `disrobe-validator` | Walks a corpus and validates every fixture round-trips, used in CI. |

## The `Pass` trait

Every pass implements one trait (`Pass` in `disrobe-core`, re-exported as `chain::detector::Pass`): it exposes a `Detector` that scores how confidently it recognizes an input, plus a `run` method that takes an `Artifact` at one rung and returns an `Artifact` one or more rungs higher. Because every pass speaks the same detector interface, the chain runner needs no per-pair compatibility table: it re-detects the current bytes after every stage and picks whichever registered pass returns the highest-confidence, highest-precedence verdict. This is what lets `PyInstaller -> PyArmor -> .pyc decompile` work as a single `disrobe auto` invocation rather than three hand-wired steps.

Each pass also exposes a standardized set of emits (`source`, `disasm`, `ast`, `cfg`, `ir`, `manifest`, `sourcemap`, `symbols`, `strings`, `imports`, `signatures`, `report`). A pass that cannot produce a given emit writes an explicit `applicable: false` stub with the `DR-IR-NotApplicable` code rather than silently dropping it.

## The four pillars

1. [The five-rung IR ladder](./ir-ladder.md): the common intermediate representation every artifact climbs.
2. [Passes and pass selection](./passes.md): what each pass registers and how the chain runner picks between them.
3. [The chain runner](./chain.md): auto-detection, stage mirrors, depth and cycle caps.
4. [The `.dr` envelope](./envelope.md): the content-addressed wire format that makes caching deterministic.

## Determinism is a design constraint, not a feature

The entire architecture exists to make output reproducible. There is no model in the decompile path, and no randomness in it either: the only generator in shipped code produces the ephemeral key for opt-in redaction (`Redactor::with_random_key` in `crates/disrobe-core/src/recon/redact.rs`), which must not be reproducible or the redaction would be reversible, and its `with_key` sibling derives a stable key when you do want repeatable output. Timing tokens are scrubbed from golden outputs so that two runs hash identically. The `.dr` envelope is content-addressed (BLAKE3) rather than timestamp-addressed, so a cache hit is provably the same bytes. This is what makes `disrobe` output usable as a forensic baseline and as a `disrobe diff` input across versions.

This is proven across real machines, not just within one process: each of the `test` job's three OS legs (Linux, macOS, Windows) runs the real CLI against the same corpus fixtures, and the downstream `determinism-cross-platform` job hashes the real recovered output with BLAKE3 and fails the build if any two operating systems disagree. A companion check on a single leg runs the same fixtures through `disrobe auto`'s batch runner, the one code path in the CLI that actually spreads work across a multi-worker thread pool, at `--jobs 1` and `--jobs 4`, and confirms the recovered bytes are identical either way. See `crates/disrobe-cli/tests/determinism_cross_platform.rs` and the `determinism-cross-platform` job in `.github/workflows/ci.yml`.
