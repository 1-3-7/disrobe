# Evidence and benchmark harness

Public, reproducible proof for every recovery claim `disrobe` makes. The core principle is credibility,
not scope: for each claim there is a dataset, a script, a result, and an external oracle that can
reject a wrong answer. A stranger runs one command and regenerates the report; a public CI log proves
it.

This tree contains no second repository. Everything lives in the `disrobe` repo: inputs in `corpus/`,
per-ecosystem runner logic in `benches/`, descriptors and rendered results here.

## One command

```sh
./evidence/run.sh            # render evidence/results/ (Linux/macOS)
pwsh evidence/run.ps1        # render evidence/results/ (Windows)
```

Both delegate to the xtask subcommand:

```sh
cargo run -p xtask -- evidence            # render results
cargo run -p xtask -- evidence --check    # drift gate: assert rendered numbers match recovery.json + floors hold
cargo run -p xtask -- evidence --list     # list discovered descriptors, strength, CI status, measured value, floor
```

`--check` is the CI drift gate. It re-renders every result and fails if any number drifts from
`xtask/data/recovery.json` (the canonical results store), or if a floor is violated. The same freshness gate runs under `cargo run -p xtask -- regen --check`, the umbrella that also covers schemas, generated bindings, error docs, the graphs, card, and demo artifacts, and a README stat cross-check, so
`evidence/results/` is held byte-fresh exactly like every other generated artifact in the repo.

## What it renders

- `evidence/results/EVIDENCE.md` - the public report: the oracle table (claim, measured number,
  external oracle, reproduce command), proven head-to-head rows, and floors.
- `evidence/results/index.json` - the machine rollup the README reads (descriptor count, ecosystems,
  floor status, per-descriptor rows).
- `evidence/results/<id>.{json,md}` - one structured + one human result per descriptor.

Every measured value is read from `xtask/data/recovery.json`; the harness never recomputes
or rounds a number. recovery.json is itself sourced per-value from a committed test gate or a local
measurement harness (the `source` field cites the exact `file:line`).

## Dependency boundary (two disjoint sets)

These are deliberately separate. The product needs the first set; only the evidence and oracle
harness needs the second.

### BUILD dependency set (what shipping `disrobe` requires)

Rust 1.95+ stable. Nothing else. `cargo build --release` produces a single binary. No Python, Node,
JVM, wasmtime, Lua, or external tool is linked into or invoked by the product at run time.

### RUNTIME / CI-VALIDATION dependency set (what grading the evidence requires, never the product)

| Ecosystem | Oracle tool (proves `disrobe` correct) | Offline | Notes |
|---|---|---|---|
| Python | CPython 3.8-3.14 (uv-provisioned) | tier 1/2 yes | recompile-to-equivalent-bytecode per code object |
| JVM | `javac` (JDK 25, setup-java) | yes | per-method recompile (recompile-only oracle) |
| Android | JVM `-Xverify:all` | committed dex yes; real APKs need fetch | verifier-attested classes are CI; real-APK coverage is `[local]` |
| WASM | wasmtime (a Rust crate dep of the test, not the product) | yes | execution differential under `--features sandbox` |
| Lua | `luac` / `lua` 5.1-5.4 | yes | recompile + execution differential |
| Ruby | MRI (`ruby`) | yes | recompile, opcode multiset |
| .NET | `dotnet` SDK / `csc` | committed samples yes | ordered CIL compare + byte-identical stdout |
| Go | go1.26.3 toolchain | yes | type metadata parsed against the real toolchain output |
| Native packers | byte-identity vs the committed original PE | yes | no external tool participates |

CI installs the runtime/validation set per ecosystem so a missing tool fails only its own lane.

This is where a reader should be careful, because the stronger claim that used to sit here was not
true. Many checks in this tree still return early and report success when the tool they need is
absent, and an audit counted several hundred such sites. Where CI provisions the tool the check does
run, and a provisioning step that fails takes its whole job down with it. Where CI does not provision
it, the check degrades to a weaker comparison or to nothing at all, and says so only on stderr. Two
figures were found to have never been enforced in CI at all for exactly this reason. Treat a number
as gated only when a workflow visibly installs the tool that measures it.

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
external = "the EXTERNAL oracle that can reject a wrong answer"
reproduce = "the exact cargo test command a stranger runs"
note = "optional caveat (e.g. recompile-only vs equivalence)"

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

The bench runs `disrobe` and the leading competing tool on the byte-identical input and grades both
sides with the same external oracle:

- `apk-jadx-cfr.json` - `disrobe` vs JADX (DEX) and CFR (JAR), recompile-clean main-class methods under
  real `javac` against a stubbed classpath (no original-jar leak).
- `frisk-apkleaks.json` - `disrobe frisk` vs apkleaks, secret/IOC recall against the hand-verified
  planted ground truth in `corpus/recon/apk/planted-secrets.apk`.
- `gate-harvest.json` - real gate oracles with no `recovery.json` number (swift demangle recall,
  frisk planted-category recall, pickle corpus coverage), each run in-process via the same public API
  its committed test exercises.

Honest losses are published in the same table as wins. A competitor that is absent or crashes counts
its samples as misses, never a dropped sample; a skipped oracle in a CI lane is a hard failure
(`.github/workflows/evidence.yml` asserts every competitor produced an `ok` result). The competitor
tools install via `competitors/install-linux.sh` and are pinned in `competitors/versions.lock`;
apkleaks's rule set is pinned at `competitors/apkleaks-regexes.json`.
