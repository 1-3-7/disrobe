# The five-rung IR ladder

Disrobe uses five intermediate representations, from original bytes to rendered source. A recovery can use several rungs or stop at one. Unpackers commonly transform raw bytes into another raw artifact; passes do not have to visit each rung in order.

[![Five representations from bytes to source](./assets/ir-ladder.png)](./assets/ir-ladder.png)

[Open the full-size IR diagram](./assets/ir-ladder.png).

The shared `disrobe-ir` enum defines `Rung::{Raw, Disasm, Mir, Hir, Surface}`. Individual backends choose the representations needed for their supported inputs.

## Raw: file bytes

The input bytes and recovered container members. Format detection, extraction, unpacking, and decryption operate here. A byte comparison can grade a recovered member when its original is available; a successful extraction alone does not establish byte identity.

## Disasm: instructions

Decoded operations with their offsets, operands, and labels. Commands such as `disrobe py disasm`, `disrobe beam disasm`, and `disrobe as3 disasm` expose instruction listings directly. The supported decoder and input format determine which bytes can be represented.

## MIR: basic blocks

Normalized operations and control flow: blocks, branches, stack effects, and values. This representation gives structural recovery a common vocabulary without requiring the original source syntax.

## HIR: program structure

Recovered loops, conditions, expressions, and other source constructs. Available names and types come from the input's metadata and the backend's analysis. Missing information can limit the structure a pass recovers.

## Surface: readable source

Rendered text in the selected output language, such as Python, Java, C#, Lua, Erlang, WAT, C, Rust, or TypeScript. Some backends produce pseudo-source. Consult the language guide and recovery report before treating an output as compilable or behaviorally equivalent to its input.

Python's published comparison recompiles output and compares normalized opcode structure. It excludes jump targets and most operands, so agreement measures that structure rather than program equivalence. See [the comparison rules and measured population](./languages/python.md#measured-opcode-structure).

## Composition and storage

The chain runner uses detectors to select passes and re-inspects each stage's output. The shared artifact envelope carries the representation and integrity metadata. Rung names describe what an artifact contains; they do not determine the next pass by themselves.

The transcode registry is keyed by `(from_version, from_rung, to_version, to_rung)`. `disrobe envelope migrate-check <from.dr> <to.dr>` checks whether a registered migration path satisfies the required capabilities.

## Confidence tiers

Recovery producers map their evidence to four tiers in `disrobe-core`:

| Tier | Assigned for |
|---|---|
| `exact` | A byte-roundtrip-verified signal. |
| `semantic` | A recompilation-equivalence or full-body-lift signal. |
| `partial` | Some recovered bodies or structured output without verification. |
| `skeleton` | Signatures only or no recovered body. |

These are producer-reported classifications. In particular, `semantic` can mean that a full body was lifted without an independent execution comparison. Read the accompanying evidence and [result documents](./reading-a-result.md) for the limits of a recovery.
