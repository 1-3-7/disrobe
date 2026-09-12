# Evidence and benchmark harness

This directory contains benchmark descriptors, measurement results and generated reports. Inputs
live in `corpus/`; measurement harnesses live in `benches/` and the test suites named by each descriptor.

`strong` results use an independent correctness reference. `coverage-self-reported` results count
features or instructions recognized by Disrobe. Per-result provenance identifies the recorded run;
regenerating a report retains the measurement's original date and source.

The figures summarize [recovery measurements](../docs/assets/recovery.png),
[Python version coverage](../docs/assets/python-versions.png) and
[the pipeline architecture](../docs/assets/architecture.png).

## Render stored evidence

```sh
./evidence/run.sh            # render evidence/results/ (Linux/macOS)
pwsh evidence/run.ps1        # render evidence/results/ (Windows)
```

Both commands render stored measurements through xtask:

```sh
cargo run -p xtask -- evidence            # render results
cargo run -p xtask -- evidence --check    # drift gate: assert rendered numbers match recovery.json + floors hold
cargo run -p xtask -- evidence --list     # list discovered descriptors, strength, CI status, measured value, floor
```

`--check` compares reports with `xtask/data/recovery.json` and checks their declared floors.
`cargo run -p xtask -- regen --check` includes this check with the other generated artifacts.

## Rerun a measurement

Select the descriptor for the claim, inspect its complete input population, and provision the pinned
tools and data its grading command requires. Run that command against the intended source revision.
Keep failures and ungraded members in the result, with exact identities and reasons. Record the
command, date, source state, tool and dataset identities, raw output, and exit status. For performance
measurements, also record hardware, operating system, repeated runs and relevant uncertainty.

Update the stored figure from the completed measurement, then render and check the dependent reports.

## What it renders

- `evidence/results/EVIDENCE.md` - the public report: the evidence table (claim, measured number,
  evidence basis, reproduce command), proven head-to-head rows, and floors.
- `evidence/results/index.json` - the machine rollup the README reads (descriptor count, ecosystems,
  floor status, per-descriptor rows).
- `evidence/results/<id>.{json,md}` - one structured + one human result per descriptor.

Every measured value is read from `xtask/data/recovery.json`; the harness never recomputes
or rounds a number. recovery.json is itself sourced per-value from a committed test gate or a local
measurement harness (the `source` field cites the exact `file:line`).

## Ground-truth corpora (`corpus/`)

`evidence/corpus/` contains paired inputs for families without an external grading tool. Each entry
includes an obfuscated input, a separate original, and metadata recording the source, seed, bit width
and variable count.

Fixture generators have their own expression model, parser, evaluator and forward rewriter under
`evidence/generators/`. `cargo run -p xtask -- health` checks the dependency graph and rejects any
generator that links a recovery crate.

Sources are ranked, and each entry records which one produced it. A real external obfuscator over an
original we chose outranks a published dataset that ships its originals, which outranks the in-house
rewriter. The last of those is width and variable-count coverage, and is regression evidence rather
than proof of capability. `evidence/corpus/<family>/sources.toml` names the tool, the pinned commit
or sha256, and the licence for each.

Each grading run must reject and identify a deliberately incorrect recovery alongside the real
results. A minimum graded-case count also prevents an empty or heavily skipped run from passing.

Grading runs two legs. The first is behavioural: the generator computed the expected value of the
original on each check vector with its own evaluator, so agreement is agreement with something the
recovery path never produced. The second is exact: when `z3` or `bitwuzla` is on PATH the gate asks
it to prove the recovered expression equal to the held-out original over every input, and it first
makes the solver refute a pair that is not equivalent so the leg cannot pass by answering nothing.
Set `DISROBE_REQUIRE_SOLVER` to make a missing solver fatal rather than skipped.

Present families:

| Family | Entries | Sources | Gate |
|---|---|---|---|
| Mixed boolean arithmetic | 316 committed | MBA-Obfuscator (100), in-house rewriter (216) | `cargo test -p disrobe-mba --test evidence_corpus_gate` |

A published dataset lane runs beside the committed one. MBA-Blast, MBA-Solver and Loki ship their
originals, but none carries a licence this repository may redistribute, so the bytes are fetched at a
pinned sha256 into `target/` rather than committed. Populate and run it with:

```sh
python evidence/generators/mba/fetch_datasets.py
cargo run -p disrobe-evidence-mba --release -- datasets --input target/mba-datasets --out target/mba-dataset-corpus
DISROBE_MBA_DATASET_CORPUS=$PWD/target/mba-dataset-corpus cargo test -p disrobe-mba --test evidence_dataset_gate
```

That lane is a `[local]` figure and is never presented as CI-attested.

## Labelled negative corpus

Every corpus above grades what `disrobe` recovers. `corpus/negative/binfmt/` grades what it must
refuse: truncated headers, declared sizes that exceed the file, overlapping sections, cyclic and
self-referential offsets, expansion-ratio lies, counts near the type maximum, a magic that does not
match its body, and a version the reader does not implement. Every member carries a label
naming its correct outcome, drawn from a closed typed vocabulary, and the harness fails when a
member that must refuse instead returns a recovery. See `evidence/negative-corpus.md`, and run it
with `cargo test -p disrobe-binfmt --test negative_corpus`.

## Dependencies

Building the CLI requires the repository's Rust toolchain and a target linker/C toolchain for native
dependencies. Windows MSVC builds also need the Visual C++ build tools and Windows SDK. See
[Installation](../docs/src/installation.md#build-from-source) for the build command and platform prerequisites.

Optional analysis backends such as Ghidra, CFR, jadx and ILSpy have their own prerequisites. Those
apply to the command and backend selected. The tools below reproduce particular measurements;
they are not prerequisites for every recovery path.

### Measurement tools

| Ecosystem | Reference tool | Offline | Notes |
|---|---|---|---|
| Python | Matching CPython interpreter | tier 1/2 yes | recompilation and normalized opcode-structure comparison; see each descriptor for exclusions |
| JVM | `javac` (JDK 25, setup-java) | yes | per-method recompile (recompile-only oracle) |
| Android | JVM `-Xverify:all` | committed dex yes; real APKs need fetch | verifier-attested classes are `[CI]`; real-APK coverage is `[local]` |
| WASM | wasmtime (a Rust crate dep of the test, not the product) | yes | execution differential under `--features sandbox` |
| Lua | `luac` / `lua` 5.1-5.4 | yes | recompile + execution differential |
| Ruby | MRI (`ruby`) | yes | recompile, opcode multiset |
| .NET | `dotnet` SDK / `csc` | committed samples yes | ordered CIL compare + byte-identical stdout |
| Go | go1.26.3 toolchain | yes | type metadata parsed against the real toolchain output |
| Native packers | byte-identity vs the committed original PE | yes | no external tool participates |

Each descriptor records its command, required inputs, reference tool and CI status. A CI label
applies to the workflow's documented triggers. A local measurement requires its listed prerequisites;
a skipped test does not reproduce its result.

## Reproducibility tiers (offline vs network)

1. Compiler-synthesized at run time and small committed golden fixtures are FULLY offline and back
   the primary `[CI]` numbers.
2. Publicly-redistributable real samples (FOSS APKs for the head-to-head comparisons in a later
   phase) need a one-time network fetch pinned by SHA-256; once cached they replay offline. Numbers
   that depend on a network fetch or a license-restricted sample are tagged `[local]`, never claimed
   as fully-offline CI-attested.

No live malware is ever fetched, stored, or executed. Malware-family unpacking is demonstrated only
on benign carriers packed with the same packer a family uses, graded byte-for-byte.

## Extending the harness (drop-in)

Adding a benchmark for a new INPUT in an existing (ecosystem, oracle) pair is a one-file drop: add a
`descriptors/<id>.toml` and the harness auto-discovers it. The descriptor id must match the filename.

A new `oracle.kind` (a metric the registry does not implement yet) needs one localized code change in
`xtask/src/evidence.rs`. `cargo run -p xtask -- evidence --list` validates every descriptor and fails
loudly on an unknown `oracle.kind` or `oracle_strength` rather than silently skipping, so a
half-wired benchmark cannot masquerade as passing.

Descriptor schema (see any file under `descriptors/`):

```toml
id = "py-stdlib-recompile"             # must equal the filename stem
ecosystem = "python"
title = "..."
claim = "..."
oracle_strength = "strong"             # strong | recompile-only | coverage-self-reported
ci = true                              # true => CI-attested [CI]; false => [local]

[oracle]
kind = "recovery-import"               # recovery-import | bench-native-unpack | headtohead-import | gate-test-harvest
external = "an external oracle, or the stated self-reported evidence basis"
reproduce = "the exact cargo test command a stranger runs"
note = "optional scope caveat (e.g. recompile-only, equivalence, or self-reported)"

[source]                               # required for kind = recovery-import
recovery_group = "<exact heading in recovery.json>"
recovery_bar = "<exact bar label in recovery.json>"
floor = 90.0                           # optional; sits below measured so a regression is caught

[measured]                             # required for headtohead-import / gate-test-harvest
result_file = "apk-jadx-cfr.json"      # under evidence/results/measured/, written by the bench
gate_id = "pickle-corpus-coverage"     # required only for gate-test-harvest
disrobe_floor = 95.0                   # optional; floors disrobe's measured value
```

## Head-to-head comparisons

`headtohead-import` and `gate-test-harvest` descriptors do not read `recovery.json`. They read the
measured JSON the head-to-head bench writes:

```sh
cargo run -p disrobe-bench-head-to-head            # run tool + competitors, write evidence/results/measured/*.json + results.md
cargo run -p disrobe-bench-head-to-head -- --check # drift gate on the measured JSON (gated to the linux canonical platform in CI)
```

The bench runs `disrobe` and the pinned competing tools on byte-identical inputs:

- `apk-jadx-cfr.json` - `disrobe` vs JADX (DEX) and CFR (JAR), compiling each tool's emitted source
  regions with `javac` against a stubbed classpath. The original JAR is excluded from that classpath.
  Each tool has its own emitted-region denominator, so this measures compilation yield rather than
  the fraction of the original program recovered. On the pinned DEX corpus,
  JADX 1.5.5 exits with status 1 after producing partial output. The scorer reconciles that exact
  output against the pinned corpus, counts five explicitly undecompiled methods as unclean, and
  records 281 of 303 emitted methods as recompilable (92.7%).
- `frisk-apkleaks.json` - `disrobe frisk` vs apkleaks, secret/IOC recall against the
  planted ground truth in `corpus/recon/apk/planted-secrets.apk`.
- `gate-harvest.json` - real gate oracles with no `recovery.json` number (frisk planted-category
  recall, pickle corpus coverage), each run in-process via the same public API
  its committed test exercises.

Every required tool must be present at its pinned version. A missing tool, unexpected exit status or
invalid result stops measurement publication. The pinned JADX partial-output case above is checked
against its fixture and output fingerprints. Raw source, compiler output and findings accompany each
run. Install the competing tools with `competitors/install-linux.sh`; versions are pinned in
`competitors/versions.lock`, and APKLeaks rules in `competitors/apkleaks-regexes.json`.

Frisk archives both its raw report and a portable copy whose root is `planted-secrets.apk!/`.
The accompanying provenance records the physical root and both hashes; findings and scan counts
are unchanged. On Windows, install JADX in a directory without spaces or shell characters so
APKLeaks 2.6.3 can invoke its launcher.
