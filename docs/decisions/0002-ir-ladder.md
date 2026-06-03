# 2. Model every recovery as a five-rung IR ladder

- Status: accepted
- Date: 2025-09-08
- Deciders: project maintainer

## Context and Problem Statement

disrobe recovers source from many unrelated ecosystems - CPython bytecode, JVM classfiles, .NET CIL, Lua chunks, WebAssembly, native PE/ELF/Mach-O. Without a shared abstraction, each ecosystem would grow its own ad-hoc pipeline, passes could not compose across ecosystems, and "how far did we get?" would mean something different for every target. We need one intermediate-representation model that every artifact climbs, so that a PyInstaller extract, a PyArmor decrypt, and a `.pyc` decompile can chain as a single operation, and so that partial recovery has a single honest meaning.

## Decision Drivers

- Cross-ecosystem **composition**: a pass from one crate must be stitchable to a pass from another without either knowing about the other.
- **Honest partial recovery**: a decompiler that reaches structured IR but cannot cleanly render source must be able to stop and emit the lower rung rather than fabricate.
- A single place to define the rungs so Python, JVM, CIL, Lua, Wasm, and native all agree.
- **Transcoding** across schema versions without changing the abstraction level.

## Considered Options

1. **A fixed five-rung ladder** - `Raw → Disasm → MIR → HIR → Surface`, defined once in `disrobe-ir` as `Rung::{Raw, Disasm, Mir, Hir, Surface}`, with each pass declaring "I take rung N, I produce rung N+1".
2. **Per-ecosystem bespoke pipelines** - each language defines its own stages; maximal local fit, zero cross-ecosystem composition.
3. **A single flat IR** - one universal instruction set everything lowers into; maximal uniformity but a poor fit for the genuinely different shapes of bytecode vs native vs CIL, and it erases the faithful-disassembly rung analysts need.

## Decision Outcome

Chosen option: **the fixed five-rung ladder**. The rungs are: **Raw** (original bytes; unpack/decrypt operate here and the "byte-identical unpack" guarantee lives here), **Disasm** (lossless 1:1 instruction decode, offsets preserved), **MIR** (control-flow-aware: basic blocks, explicit CFG, stack effects resolved, super-instructions un-fused; the Python frame-tree pre-pass runs here), **HIR** (structured control flow, names/types/idioms recovered, language-shaped but not yet text), and **Surface** (final rendered source, where the Python round-trip metric runs).

## Consequences

- **Good:** because a pass only declares "rung N → rung N+1", the chain runner composes passes from different crates with no coupling between them - this is what makes `PyInstaller → PyArmor → .pyc decompile` one `disrobe auto` invocation.
- **Good:** partial recovery is honest and uniform - a pass that reaches HIR but cannot render Surface emits the HIR/Disasm artifact tagged `partial` or `skeleton`, rather than inventing source. Confidence tiers (`exact`, `semantic`, `partial`, `skeleton`) propagate into `recovery.json` and the `--llm` bundle.
- **Good:** several tools deliberately stop at Disasm (`disrobe py disasm`, `beam disasm`, `as3 disasm`, `pickle disasm`), which the ladder makes a first-class, well-defined endpoint rather than a half-finished decompile.
- **Bad / accepted cost:** the ladder is a Procrustean fit for ecosystems whose natural pipeline has more or fewer stages; passes occasionally do more than one rung's worth of work between declared boundaries. We accept this for the composition payoff.
- **Bad / accepted cost:** a pass that cannot produce a standardized emit must write an explicit `applicable: false` stub (`DR-IR-NotApplicable`) rather than silently dropping it, which is more code but preserves the honesty invariant.
