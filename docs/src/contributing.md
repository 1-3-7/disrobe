# Contributing

Contributions are welcome under the [Contributor Covenant 2.1](https://github.com/1-3-7/disrobe/blob/main/.github/CONTRIBUTING.md).

## Building and testing

**disrobe** builds with a single stable Rust 1.95+ toolchain:

```sh
cargo build --release
cargo test -p <crate>          # test a single crate
```

> The JVM decompiler can be memory-intensive on adversarial input. Prefer per-crate test runs over a bare workspace-wide `cargo test --workspace` when iterating locally.

## The quality bar

Every commit on `main` must pass the workspace clippy gate with zero warnings:

```sh
cargo clippy --all-targets -- -D warnings -W unreachable_pub -W missing_debug_implementations -W unused
cargo fmt --all -- --check
```

The workspace lints are strict by design: `unwrap_used` is denied, `todo!` and `unimplemented!` are denied, and `unsafe` is forbidden outside the two C-interop crates. New code is fully type-annotated and self-documenting; the codebase carries durable context in dedicated docs rather than inline comments.

## Adding a pass

A new ecosystem pass is a new `disrobe-pass-<name>` crate that:

1. Implements the shared `Pass` trait, declaring its required and produced capabilities and its rung transition.
2. Climbs the [five-rung IR ladder](./ir-ladder.md) rather than jumping rungs.
3. Ships a `pass_run_envelope_roundtrip` test and at least one real-fixture integration test in `crates/disrobe-cli/tests/`.
4. Wires its standardized emits, returning explicit `applicable: false` stubs for emits it cannot produce.

Every capability claim must be backed by a fixture in `corpus/` and a passing test - nothing aspirational ships as done. Fixtures are baked locally from known-good inputs by `corpus/generate.{sh,ps1}`; copyrighted third-party obfuscated bytecode is never committed to the public corpus.

## Honesty over hype

**disrobe** had a fabrication audit early in its life, and the lesson stuck: a decode that only passes against synthetic, self-generated fixtures is not a feature. Per-pass work is verified against a real corpus and the upstream format spec. Partial recovery is labelled honestly with a confidence tier; detect-only is stated as detect-only. If you are not sure a capability works against real-world input, say so in the PR.

## Reporting bugs

Generate an environment report to attach to an issue:

```sh
disrobe bug-report --out report.md
disrobe bug-report --out -          # write to stdout
```

For security issues, do not open a public issue - use the [private advisory channel](https://github.com/1-3-7/disrobe/security/advisories/new). See [Security](./security.md).
