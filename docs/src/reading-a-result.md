# Reading a result

A run that recovers everything needs no interpretation. This page is for the other case: the chain stopped short, a body came back thin, or a pass declined to answer. Each section below is a symptom you can see in the output, what that symptom means, and the command to run next.

Two things before the symptoms. `disrobe` does not emit a recovery it cannot justify from the input, so a stated refusal is a result rather than a failed run; the reasoning is in [refusal is a result](./introduction.md#refusal-is-a-result). And "did not recover" and "cannot be recovered" are different claims. The output distinguishes them, and most of the work of reading a result is telling which one you have.

## What a run leaves behind

`disrobe auto` and `disrobe chain` write three documents into the output directory.

| File | Contents |
|---|---|
| `chain.json` | The executed topology, schema `disrobe.chain/v1`. One node per stage with its pass id, input and output BLAKE3, sizes, the detector pick that selected it, a per-stage verdict, optional registered string metadata, and an `error` string when a stage failed. |
| `recovery.json` | The per-run report, schema `disrobe.recovery/v1`. Each stage's status and confidence tier, a tier histogram, and timings. |
| `anti-analysis.json` | Anti-analysis techniques observed across the run. See [anti-analysis defeat](./anti-analysis.md). |

Read `recovery.json` through `disrobe context` instead of by hand:

```sh
disrobe auto sample.bin --out ./out/sample --capture-stages
disrobe context --out ./out/sample
```

That prints the input identity, the overall chain verdict, the tier histogram, and one row per stage:

```text
disrobe context  (./out/sample)
  schema:    disrobe.recovery/v1
  input:     sample.bin (257 bytes, blake3 b6d7bc82...)
  verdict:   Complete
  total_ms:  187
  tiers:     exact=0 semantic=1 partial=0 skeleton=0 (total 1)
  passes:
    py.decompile                 recovered  semantic  0ms
```

`disrobe report ./out/sample` renders the same run as text, markdown, JSON, or a self-contained HTML page, and adds a recovery score, the artifact inventory, and the detect-only and skeleton caveats. See [run reports](./cli/report.md).

Pass `--capture-stages` on any run you expect to have to debug. It mirrors each stage's byte-exact output to `./out/sample/NN-<pass>/output.bin` and links the terminal stages under `./out/sample/final/`, which is what lets you re-enter the pipeline at the stage that stopped. Without it you have the verdicts but not the bytes.

## Two vocabularies, and one word they share

`disrobe` labels two different things, and `partial` appears in both.

A **support tier** describes a family, not a run. It is the standing claim about how far recovery goes for that packer or obfuscator, and it comes from [the catalog](./catalog.md) or `disrobe catalog <ecosystem>`: `Recover`, `Partial`, or `Detect-only`.

A **confidence tier** describes one stage of one run. It comes from `recovery.json`, and the four values, ranked, are `exact`, `semantic`, `partial`, `skeleton` (`ConfidenceTier` in `crates/disrobe-core/src/recovery.rs`). A family at support tier `Recover` can still produce a `skeleton` stage on your sample. The first is what the pass can do, the second is what it did here.

Stage status is a third axis, with five values:

| Status | Set when |
|---|---|
| `recovered` | The stage completed with output, or extracted children. |
| `advanced` | The stage produced output the chain then fed onward. |
| `incomplete` | The branch ended at a stall, a cycle, or a cap. |
| `failed` | The pass returned an error, which includes a stated refusal. |
| `skipped` | A plan-only run (`disrobe auto --dry-run`), where nothing executed. |

## The chain stopped early

**Symptom.** Chain verdict `Stalled` in the text view, `"stalled"` in JSON. The last `disrobe context` row is named `terminal`, with status `incomplete` and confidence `skeleton`:

```text
  verdict:   Stalled
  tiers:     exact=0 semantic=0 partial=0 skeleton=1 (total 1)
  passes:
    terminal                     incomplete skeleton  -
```

**Meaning.** Every registered detector ran against that stage's bytes and none returned a confidence at or above the selection floor of 0.5, so the runner stopped rather than run a pass it does not believe applies. This is a statement about detection, not about the bytes. It is also why the row has no pass name: no pass executed at that node, so there is nothing to attribute the tier to.

`chain.json`'s `stats.rejected_passes` counts candidates dropped below the floor across the run. Zero means nothing recognized the bytes at all. Nonzero means something did recognize them, just not confidently enough to act on, and that is the more promising case.

**Next.** Identify the stalled bytes yourself, then name the pass instead of letting detection choose it.

```sh
disrobe detect ./out/sample/final/02-pyinstaller-extract/output.bin
disrobe identify ./out/sample/final/02-pyinstaller-extract/output.bin
disrobe chain sample.bin --chain 'pyinstaller.extract,pyarmor.unpack,py.decompile' --out ./out/sample-explicit
```

An explicit `--chain` bypasses detector selection for the passes you name, so a family that scored 0.4 still gets its pass run. Chain pass ids are dotted and comma-separated (`pyinstaller.extract`, `pyarmor.unpack`, `py.decompile`, `native.packer-unpack`, `binfmt.container`, and the rest), and a trailing `,*` hands the remaining depth back to auto-detection. These are not the command groups `disrobe passes` prints; an id the registry does not know fails with `DR-CLI-0298` and lists every id it does know, which is the quickest way to see them all.

When `auto` recovers nothing it already prints a note on stderr naming the format it thinks it saw and the command group to try:

```text
note: auto recovered no files and could not identify the format. Run `disrobe detect <file>` to identify it, then the matching subcommand.
```

## The chain hit a cap

**Symptom.** Verdict `CapReached`, or `"cap-reached"` in JSON, on a branch that still had unprocessed output.

**Meaning.** One of two bounds stopped the branch. Either the depth cap, eight passes by default, or the cumulative-output budget of 512 MiB across the whole run. Both exist so a nested archive or a self-re-emitting packer cannot make a chain run forever; see [depth and cycle safety](./chain.md#depth-and-cycle-safety). Nothing about the input is being claimed here. The stages that did run are valid and their outputs are on disk.

**Next.** Raise the depth cap, or split the work and re-enter on the child you care about.

```sh
disrobe auto sample.bin --max-depth 16 --out ./out/sample --capture-stages
disrobe auto ./out/sample/final/03-binfmt-container/output.bin --out ./out/sample-inner
```

Sixteen is the ceiling for `--max-depth`; above it the spec is rejected. The cap is also settable per project as `max_depth` under `[execution]` in `.disrobe.toml`. The byte budget is fixed and not exposed as a flag, so a run that exhausts it has to be split.

## The chain saw the same bytes twice

**Symptom.** Verdict `Cycle`.

**Meaning.** A stage produced bytes already seen earlier in the chain. Each stage output is content-hashed with BLAKE3, and a repeat stops the branch instead of looping. Usually this is a pass that did not change its input, or an archive that contains itself.

**Next.** Compare `input_blake3` and `output_blake3` across the nodes in `chain.json` to find the stage that repeated, then run that stage's pass directly on the captured bytes to see what it did and did not change.

## A body came back as a skeleton

**Symptom.** Confidence `skeleton` on a stage that did execute, or a nonzero `skeleton` count in the histogram.

**Meaning.** The chain assigns `semantic` to a stage that completed with source output and `partial` to one that completed with a byte payload. Everything else is `skeleton`, so at chain level the tier tells you the stage did not produce a recognized recovery, not how much of each body survived. For that, read the pass's own output. Passes that recover bodies separate the levels explicitly rather than mixing them: `disrobe nuitka decompile` writes real source lifted from frozen bytecode into `frozen/` and typed signatures of native-compiled modules into `skeleton/`, and labels each in its `disrobe.nuitka.recovery-manifest/v1` sidecar (`decompiled-from-bytecode` against `signatures-only-native-compiled`), so no signature is ever presented as a recovered body.

The question that matters next is whether the missing part is in the artifact at all. A skeleton because a lifter has a gap is worth pushing on. A skeleton because the body is decrypted by a key that exists only at run time is not. The code the pass emitted is what distinguishes them.

**Next.** Check the family's standing support tier, then read the code the pass emitted.

```sh
disrobe catalog python
disrobe explain DR-PYARM-0013
```

Where a pass recovers names and signatures but no bodies, that can be the ceiling for a stripped or AOT-compiled artifact rather than a gap to push on. The family's catalog tier tells you which to expect before you spend time on it.

## A pass reported a refusal

**Symptom.** Status `failed` on a stage, with a `DR-` code in the message. In `chain.json` that node's verdict is `"error"` and the message is in its `error` field.

**Meaning.** A pass returns an error both when it malfunctions and when it declines to answer, so `failed` alone does not tell you which. The code does. A refusal names the evidence it lacked, and it is the intended outcome when the alternative would be a guess: a wrong recovery in malware analysis produces a wrong conclusion, and it produces it in a form that looks exactly like a right one.

**Next.** Look the code up. Every failure carries a `DR-<DOMAIN>-<NNNN>` code, and `explain` prints its description, causes, and fixes:

```sh
disrobe explain DR-PYARM-0013
disrobe explain pyarm-13          # short form, zero-padded for you
disrobe explain pyarmor-13 --json # long domain aliases also resolve
```

```text
DR-PYARM-0013
  title:       PyArmor v3/v4/v5 capsule walled on the RSA-wrapped key
  description: v3-v5 capsule structure and metadata parse, but the bytecode AES key is
               RSA-wrapped with a private key the author never ships, so the plaintext is
               not in the artifact and cannot be recovered statically.
  common fixes:
    - supply the cleartext capsule key if you hold it; structure, version, and metadata
      still parse without it
```

That entry is the shape to look for. It states what did parse, what is absent, and the one input that would reopen it. Not every code in the binary has a registered entry; the domains that carry entries are `CLI`, `PYARM`, `PYINST`, `PYFRZ`, `NUITKA`, `SDEF`, `PYDEOB`, `JSDEOB`, `WASMDEOB`, `MARSHAL`, and `BINFMT`. An unregistered code returns `DR-CLI-0102` and asks you to file an issue with the full message you saw.

## The absent-data case

Some refusals are scoped to your input and reopen with a wider one. A missing PyArmor runtime extension, a wrapper another obfuscator post-processed, a `.pyc` without its matching interpreter: supply the missing piece and the recovery proceeds.

Others do not reopen. When the data is not in the artifact, no static tool recovers it, and nothing you can derive from that artifact changes the answer. Three shapes account for almost all of them: a key that exists only at run time, state that exists only in a live process, and a payload fetched from the network on execution. `disrobe` reports these as detect-only and names which shape applies, rather than emitting a body at a lower confidence tier. This is the case the whitepaper calls a wall, and [the catalog](./catalog.md) marks it per family.

The distinction is worth holding onto when you decide whether to keep pushing. A detect-only row with a named absent-data reason is a finished answer about that artifact. A stall, a cap, or a lifter gap is not.

## The recovery did not verify

**Symptom.** `disrobe py decompile` prints a `roundtrip:` line that is not `perfect`.

**Meaning.** Every Python decompile is recompiled on the matching interpreter and compared opcode for opcode. The label reports what that check found:

| Label | Meaning |
|---|---|
| `perfect` | The recompiled code object is byte-identical in code, consts, names, and varnames, nested objects included. |
| `semantic` | Not byte-identical, but the normalized opcode sequences match op for op. |
| `code-diff` | The normalized sequences differ. The detail names the qualified name and the first differing index. |
| `no-interpreter` | No matching interpreter was found, so the check did not run. |
| `recompile-failed` | The emitted source did not compile. The captured stderr says why. |
| `skipped` | The check was disabled with `--no-roundtrip`. |

`no-interpreter` and `skipped` are the two to watch, because in both the source is unverified rather than verified-and-different. Install the interpreter the `interpreter:` line names, drop `--no-roundtrip`, and run it again.

## The emit you asked for is not there

**Symptom.** An `--emit` kind wrote a small JSON document instead of an artifact.

**Meaning.** Every pass answers all twelve emit kinds. A pass that cannot produce a given kind writes an explicit stub with `"applicable": false`, `"schema": "disrobe.emit.stub/v0"`, and a `reason` that usually names the pass to chain with instead. This is so a downstream tool always gets a well-formed answer. See [standardized emits](./passes.md#standardized-emits).

**Next.** Run the pass the reason names. `disrobe auto --emit` accepts only `recovery`, which echoes `recovery.json` to stdout under `--json`; for structured emits, drive the per-language subcommand directly.

```sh
disrobe auto sample.bin --emit recovery --json --out ./out/sample
disrobe py decompile ./out/sample/final/02-pyarmor-unpack/output.bin --emit source,disasm,report
```

## Before you conclude anything

Anything you read out of a run is a claim about the bytes you supplied. Confirm the input identity in `recovery.json` matches the sample you meant to analyze: the `blake3` and `size` fields are there so a report can be tied back to an artifact, and so two runs can be compared. `disrobe diff` and `disrobe guard verify` compare `chain.json` documents stage by stage when you need to prove two runs agree. For handling of the sample itself, read [forensics and malware-safety posture](./forensics-safety.md).
