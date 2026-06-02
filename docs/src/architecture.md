# Architecture overview

disrobe is a workspace of focused Rust crates orchestrated by one CLI. Every recovery flows through the same shape: bytes in, a chain of **passes** that each transform the artifact up the **IR ladder**, an optional **`.dr` envelope** for content-addressed caching, and a final emit.

## The shape of a recovery

```text
                   ┌──────────────────────────────────────────────┐
   input bytes ──> │  detect  ──>  pass 1  ──>  pass 2  ──>  ...    │ ──> recovered artifact
                   └──────────────────────────────────────────────┘
                          │           │            │
                          │           │            └─ each pass: raw -> disasm -> mir -> hir -> surface
                          │           └─ capability resolver gates what can run next
                          └─ chain runner records chain.json + stage mirrors + recovery.json
```

## Crate map

The workspace splits into a small set of shared cores and one crate per ecosystem pass:

| Crate | Role |
|---|---|
| `disrobe-core` | Shared types: error codes (`DR-<DOMAIN>-<NNNN>`), progress, confidence tiers, secret/credential scanning, cyclomatic metrics. |
| `disrobe-ir` | The five-rung IR ladder, the `.dr` envelope (rkyv hot + postcard cold + BLAKE3 root), transcoders, capability descriptors. |
| `disrobe-binfmt` | Container and archive layer (26 formats) with shared zip-slip and decompression-bomb quota machinery. |
| `disrobe-llm-metadata` | The `--llm` sidecar: 18 categories, 4 packs, `AGENTS.md` / `SKILL.md` brief generation. |
| `disrobe-mcp` | The rmcp Model Context Protocol companion wired to `disrobe serve --mcp`. |
| `disrobe-py-marshal` | CPython marshal reader: code objects across 1.0-3.15. |
| `disrobe-pass-*` | One crate per ecosystem (py-decompile, py-disasm, py-deob, pyarmor, pyinstaller, pyfreeze, nuitka, js-deob, wasm-deob, jvm, dotnet, native, go, lua, php, ruby, beam, pickle, swift-objc, as3, mobile, sourcedefender). |
| `disrobe-cli` | The `disrobe` binary: argument parsing, output formats, the chain runner, the daemon. |
| `disrobe-validator` | Walks a corpus and validates every fixture round-trips, used in CI. |

## The `Pass` trait

Every pass implements one trait. A pass takes a `.dr` envelope at some rung, does its work, and returns an envelope one or more rungs higher, declaring which **capabilities** it requires on the way in and which it produces on the way out. Because every pass speaks the same envelope dialect, the chain runner can compose any pass with any other as long as the capability resolver is satisfied. This is what lets `PyInstaller -> PyArmor -> .pyc decompile` work as a single `disrobe auto` invocation rather than three hand-wired steps.

Each pass also exposes a standardized set of emits (`source`, `disasm`, `ast`, `cfg`, `ir`, `manifest`, `sourcemap`, `symbols`, `strings`, `imports`, `signatures`, `report`). A pass that cannot produce a given emit writes an explicit `applicable: false` stub with the `DR-IR-NotApplicable` code rather than silently dropping it.

## The four pillars

The rest of this section expands each pillar:

1. [The five-rung IR ladder](./ir-ladder.md) — the common intermediate representation every artifact climbs.
2. [Passes and the capability model](./passes.md) — how passes declare and resolve what they need.
3. [The chain runner](./chain.md) — auto-detection, stage mirrors, depth and cycle caps.
4. [The `.dr` envelope](./envelope.md) — the content-addressed wire format that makes caching deterministic.

## Determinism is a design constraint, not a feature

The entire architecture exists to make output reproducible. There is no model in the decompile path. RNG-backed backends take an explicit `--seed`. Timing tokens are scrubbed from golden outputs so that two runs hash identically. The `.dr` envelope is content-addressed (BLAKE3) rather than timestamp-addressed, so a cache hit is provably the same bytes. This is what makes disrobe output usable as a forensic baseline and as a `disrobe diff` input across versions.
