# Reading a result

Start by confirming the input identity, then inspect the recovered artifacts and the stages that stopped. The reports let you connect a result to the bytes supplied and decide whether another pass, tool, or input can help. A source file, a symbol list, and a detection report provide different evidence; the output's presence alone does not establish complete recovery.

## What a run leaves behind

`disrobe auto` and `disrobe chain` write four documents into the output directory.

| File | Contents |
|---|---|
| `chain.json` | The executed topology, schema `disrobe.chain/v1`. One node per stage with its pass id, input and output BLAKE3, sizes, the detector pick that selected it, a per-stage verdict, optional registered string metadata, and an `error` string when a stage failed. |
| `recovery.json` | The per-run report, schema `disrobe.recovery/v1`. Each stage's status and confidence tier, a tier histogram, and timings. |
| `anti-analysis.json` | Anti-analysis techniques observed across the run. See [anti-analysis defeat](./anti-analysis.md). |
| `report.json` | The forensic summary rendered by [`disrobe report`](./cli/report.md), including findings and their evidence. |

Use `disrobe context` for a terminal summary of `recovery.json`:

```sh
disrobe auto sample.bin --out ./out/sample --capture-stages
disrobe context --out ./out/sample
```

The summary prints the input identity, overall verdict, tier histogram, and stage rows. This recorded run on the repository's `corpus/webview/tauri/wvfix.exe` fixture used version 0.10.5; its timings describe that run:

```text
  schema:    disrobe.recovery/v1
  tool:      0.10.5
  verdict:   FanOutPartial
  total_ms:  468
  tiers:     exact=0 semantic=1 partial=0 skeleton=11 (total 12)
  passes:
    webview.carve                advanced   skeleton  53ms
    terminal                     incomplete skeleton  -
```

`disrobe report ./out/sample` renders the same run as text, markdown, JSON, or a self-contained HTML page, and adds a recovery score, the artifact inventory, and the detect-only and skeleton caveats. See [run reports](./cli/report.md).

Pass `--capture-stages` on any run you expect to debug. It mirrors the exact bytes written by each stage to `./out/sample/NN-<pass>/output.bin` and links the terminal stages under `./out/sample/final/`, which lets you re-enter the pipeline at the stage that stopped. Exact capture does not mean a decompiler's source output is byte-identical to the compiled input. Without capture you have the verdicts but not the stage bytes.

## Support, confidence, and status

Read these labels together: the family's supported recovery, the confidence assigned to this stage, and the stage's execution status.

A **support tier** describes a family, not a run. It is the standing claim about how far recovery goes for that packer or obfuscator, and it comes from [the catalog](./catalog.md) or `disrobe catalog <ecosystem>`: `Recover`, `Partial`, or `Detect-only`.

A **confidence tier** describes one stage of one run. It comes from `recovery.json`, and the four values, ranked, are `exact`, `semantic`, `partial`, `skeleton`. A family at support tier `Recover` can still produce a `skeleton` stage on your sample. Check the pass's output and verification result to determine which bodies or structures were recovered.

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

**Meaning.** No detector result for that stage's bytes met the selection floor of 0.5. The runner stopped because it could not select a pass with sufficient confidence. No pass executed at that node, so the terminal row has no pass name to attribute a recovery to. A stall does not establish that the input is unrecoverable.

`chain.json`'s `stats.rejected_passes` counts candidates dropped below the floor across the run. A nonzero count records low-confidence detections somewhere in the run; it does not identify the stalled artifact by itself.

**Next.** Identify the stalled bytes, then select a supported pass explicitly if its input requirements match. The stage path below is an example; use the path from your capture.

```sh
disrobe detect ./out/sample/final/02-pyinstaller-extract/output.bin
disrobe identify ./out/sample/final/02-pyinstaller-extract/output.bin
disrobe chain sample.bin --chain 'pyinstaller.extract,pyarmor.unpack,py.decompile' --out ./out/sample-explicit
```

An explicit `--chain` bypasses detector selection for the passes you name, so a family that scored 0.4 still gets its pass run. It does not supply missing keys or make an unsupported input valid. Chain pass IDs are dotted and comma-separated (`pyinstaller.extract`, `pyarmor.unpack`, `py.decompile`, `native.packer-unpack`, `binfmt.container`, and the rest), and a trailing `,*` hands the remaining depth back to auto-detection. `disrobe passes` lists the chain IDs available in your binary after its direct-command summary. An unknown ID fails with `DR-CLI-0298` and lists the registered IDs.

When `auto` recovers nothing it already prints a note on stderr naming the format it thinks it saw and the command group to try:

```text
note: auto recovered no files and could not identify the format. Run `disrobe detect <file>` to identify it, then the matching subcommand.
```

## The chain hit a cap

**Symptom.** Verdict `CapReached`, or `"cap-reached"` in JSON, on a branch that still had unprocessed output.

**Meaning.** One of two bounds stopped the branch: the depth cap, eight passes by default, or the cumulative-output budget of 512 MiB across the whole run. Both bound work on nested archives and repeatedly emitted output; see [depth and cycle safety](./chain.md#depth-and-cycle-safety). A cap records unfinished processing. Inspect the completed stages and their captured output before deciding how to continue.

**Next.** If the report identifies the depth cap, increase it within the supported limit. Otherwise, split the work and re-enter on the captured child you need to examine. Substitute its actual capture path in the second command:

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

Check whether the report identifies a missing lifter operation or data absent from the artifact, such as a runtime-only decryption key. A different recovery engine may handle the former. The latter requires additional material; retrying the same bytes cannot supply it.

**Next.** Check the family's standing support tier, then read the code the pass emitted.

```sh
disrobe catalog python
disrobe explain DR-PYARM-0013
```

Names and signatures can still locate modules or functions for further analysis. Keep their `signatures-only` status with the result so a consumer does not treat them as recovered implementations.

## A pass reported a refusal

**Symptom.** Status `failed` on a stage, with a `DR-` code in the message. In `chain.json` that node's verdict is `"error"` and the message is in its `error` field.

**Meaning.** A pass can return an error for a processing failure or a deliberate refusal, so `failed` alone does not distinguish them. Read the code and full message. A refusal should identify the unsupported condition or missing evidence; retain that limitation with any recovered artifacts.

**Next.** Look up the `DR-<DOMAIN>-<NNNN>` code. For registered entries, `explain` prints the description, causes, and fixes:

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

This entry separates what parsed from what is absent and names the additional input recovery requires. Not every code in the binary has a registered entry; the domains that carry entries are `CLI`, `PYARM`, `PYINST`, `PYFRZ`, `NUITKA`, `SDEF`, `PYDEOB`, `JSDEOB`, `WASMDEOB`, `MARSHAL`, and `BINFMT`. An unregistered code returns `DR-CLI-0102` and asks you to file an issue with the full message you saw.

## The absent-data case

Some failures identify a prerequisite you can supply: a missing PyArmor runtime extension, a wrapper altered by another obfuscator, or a `.pyc` without the interpreter needed for verification. Supplying that prerequisite allows the affected step to run; its result still needs inspection.

Other cases require data outside the supplied artifact: a key that exists only at run time, state held in a live process, or a payload fetched from the network on execution. Static recovery of the supplied bytes cannot reconstruct that missing material. [The catalog](./catalog.md) marks these detect-only cases per family and identifies the missing input.

Record the missing input when handing the result to another analyst. A detect-only result with an absent-data reason calls for additional evidence; a stall, cap, or lifter gap calls for a different recovery step.

## The recovery did not verify

**Symptom.** `disrobe py decompile` prints a `roundtrip:` line that is not `perfect`.

**Meaning.** By default, Python decompilation attempts to recompile the emitted source on a matching interpreter and compare the code objects. The label reports the comparison or why it did not run:

| Label | Meaning |
|---|---|
| `perfect` | The recompiled code object is byte-identical in code, consts, names, and varnames, nested objects included. |
| `semantic` | Not byte-identical, but the normalized opcode sequences match op for op. |
| `code-diff` | The normalized sequences differ. The detail names the qualified name and the first differing index. |
| `no-interpreter` | No matching interpreter was found, so the check did not run. |
| `recompile-failed` | The emitted source did not compile. The captured stderr says why. |
| `skipped` | The check was disabled with `--no-roundtrip`. |

For `no-interpreter`, install the matching interpreter and rerun the command. For `skipped`, remove `--no-roundtrip` to enable the comparison. Neither status reports a comparison result.

The `semantic` label refers to the documented opcode normalization, not an execution comparison. Read the [Python comparison rules](./languages/python.md#measured-opcode-structure) before using it as evidence about behavior.

## The emit you asked for is not there

**Symptom.** An `--emit` kind wrote a small JSON document instead of an artifact.

**Meaning.** Commands that implement the standardized emit contract return either the requested artifact or a stub with `"applicable": false`, `"schema": "disrobe.emit.stub/v0"`, and a reason. The shared parser recognizes fifteen emit labels, but support is command-specific and `auto` accepts only `recovery`. See [standardized emits](./passes.md#standardized-emits).

**Next.** Run the pass the reason names. `disrobe auto --emit` accepts only `recovery`, which echoes `recovery.json` to stdout under `--json`; for structured emits, drive the per-language subcommand directly.

```sh
disrobe auto sample.bin --emit recovery --json --out ./out/sample
disrobe py decompile ./out/sample/final/02-pyarmor-unpack/output.bin --emit source,disasm,report
```

## Before you conclude anything

Anything you read out of a run is a claim about the bytes you supplied. Confirm the input identity in `recovery.json` matches the sample you meant to analyze: the `blake3` and `size` fields are there so a report can be tied back to an artifact, and so two runs can be compared. `disrobe diff` and `disrobe guard verify` compare `chain.json` documents stage by stage when you need to prove two runs agree. For handling of the sample itself, read [forensics and malware-safety posture](./forensics-safety.md).
