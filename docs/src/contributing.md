# Contributing

Contributions are welcome; see the [contributing guide](https://github.com/1-3-7/disrobe/blob/main/.github/CONTRIBUTING.md).

## Building and testing

`disrobe` builds with a single stable Rust 1.95+ toolchain:

```sh
cargo build --release
cargo test -p <crate> --features <the crate's test features>   # test a single crate
```

> The JVM decompiler can be memory-intensive on adversarial input. Prefer per-crate test runs over a bare workspace-wide `cargo test --workspace` when iterating locally.

### Name the features a crate hides its tests behind

Some crates keep whole modules behind a feature that is off by default. Every pass crate keeps its
chain detector behind a non-default `chain` feature so the slim build can leave the chain runtime
out. The file starts with `#![cfg(feature = "chain")]`, so a per-crate run that names no feature
builds none of the chain detector's tests and still prints a passing result for the tests it did
build. Name the feature to run them:

```sh
cargo test -p disrobe-pass-lua --features chain
cargo test -p disrobe-cli --no-default-features --features chain --test auto_dalvik_feature_gate
cargo test -p disrobe-pass-wasm-deob --features chain,sandbox --test linear_memory_local_offset
```

The second form covers a refusal that exists only when `chain` is enabled and `jvm` is disabled.
The WebAssembly differential requires `sandbox` for Wasmtime execution and `chain` for the
registered-pass assertion.

`cargo run -p xtask -- health` enforces this. It reads every crate's default feature set, finds
every test-bearing file the default set removes, and fails when a crate hides tests that no entry in
`HIDDEN_TEST_SURFACE` in `xtask/src/feature_gated_tests.rs` declares. It also reads every per-crate
test command written in the README, in `docs/src`, and in the workflows, and fails when one of them
names a test target the command's own feature set compiles away, or names no feature for a crate
that hides tests. The failure names the crate and prints the command to use instead.

## The quality bar

Every commit on `main` must pass the workspace clippy gate with zero warnings:

```sh
cargo clippy --all-targets -- -D warnings -W unreachable_pub -W missing_debug_implementations -W unused
cargo fmt -p <crate> -- --check
```

The workspace lints are strict by design: `unwrap_used` is denied, `expect_used` is treated as a defect in production paths, and `todo!` and `unimplemented!` are denied. New code is fully type-annotated and self-documenting; the codebase carries durable context in dedicated docs rather than inline comments. Unsafe code is restricted to audited boundary code and does not belong in ordinary parsing or recovery paths.

## README graphs

The dark-theme benchmark and architecture SVGs in the README are generated, not drawn by hand. The data lives in `xtask/data/*.json` (every plotted value cites its source gate or harness inline), and `xtask` renders deterministic SVGs into `docs/assets/`:

```sh
cargo run -p xtask -- graphs            # regenerate docs/assets/*.svg
cargo run -p xtask -- graphs --check    # fail if committed SVGs are stale (CI runs this)
```

After changing a number in `xtask/data/`, rerun `graphs` and commit the regenerated SVGs; the `graphs` CI job rejects any drift. Numbers come only from a committed test gate or a local measurement harness, never from the tool grading its own output, and no competitor recovery percentage is plotted.

## Docs and the wiki

These pages under `docs/src` are the single source of truth. The GitHub wiki is generated from them by `scripts/wiki_sync.py` and the `wiki-sync` workflow, which runs on every push to `main` that touches `docs/`. Do not edit the wiki directly; it is overwritten on the next sync. Edit the page here, then preview the generated wiki locally:

```sh
python scripts/wiki_sync.py --out ./.wiki-build       # build the wiki tree
python scripts/wiki_sync.py --check --out ./.wiki-build  # fail on drift
```

## Adding a pass

A new ecosystem pass is a new `disrobe-pass-<name>` crate that:

1. Implements the shared `Pass` trait, declaring its required and produced capabilities and its rung transition.
2. Climbs the [five-rung IR ladder](./ir-ladder.md) rather than jumping rungs.
3. Ships a `pass_run_envelope_roundtrip` test and at least one real-fixture integration test in `crates/disrobe-cli/tests/`.
4. Wires its standardized emits, returning explicit `applicable: false` stubs for emits it cannot produce.

Every capability claim must be backed by a fixture in `corpus/` and a passing test; nothing aspirational ships as done. Fixtures are baked locally from known-good inputs by `corpus/generate.{sh,ps1}`; copyrighted third-party obfuscated bytecode is never committed to the public corpus.

## No fabrication

A decode that only passes against synthetic, self-generated fixtures is not a feature. Per-pass work is verified against a real corpus and the upstream format spec. Partial recovery carries a confidence tier; detect-only is stated as detect-only. If you are not sure a capability works against real-world input, say so in the PR.

## Reporting bugs

Generate an environment report to attach to an issue:

```sh
disrobe bug-report --out report.md
disrobe bug-report --out -          # write to stdout
```

For security issues, do not open a public issue; use the [private advisory channel](https://github.com/1-3-7/disrobe/security/advisories/new). See [Security](./security.md).
