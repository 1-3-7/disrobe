# Contributing

## Getting started

```
git clone https://github.com/1-3-7/disrobe
cd disrobe
cargo build --workspace
cargo test --workspace
```

You'll need Rust stable (see `rust-toolchain.toml` for the pinned version). Nothing else is strictly required, though `lefthook` is recommended for pre-commit checks:

```
cargo install lefthook
lefthook install
```

## Branch model

`main` is always releasable. Work in feature branches, open a PR, squash-merge when green.

Branch naming: `pass/<name>`, `fix/<slug>`, `feat/<slug>`, `refactor/<slug>`. Keep them short-lived.

## Commit messages

Imperative mood, 72-character subject line, no period. Body is optional; use it for non-obvious motivation, not for restating what the diff shows.

```
Add PyArmor v8 co_code reconstruction pass

Jumptable dispatch sequences in newer builds need backtracking;
this commit adds a small symbolic executor for the three-opcode pattern.
```

## Code standards

- `Result` everywhere at fallible boundaries. No `.unwrap()` in library code; `.expect("invariant: ...")` is acceptable when the invariant is genuinely unbreakable.
- `HashMap` / `HashSet` are banned from emit paths via `clippy.toml`. Use `IndexMap` / `IndexSet` (or `BTreeMap` / `BTreeSet` for sorted output). The linter will tell you.
- No `SystemTime::now()` or unseeded randomness inside passes. Route through `disrobe_core::time` and `disrobe_core::rng` so determinism can be enforced end-to-end.
- Run `cargo clippy --workspace --all-targets -- -D warnings` before pushing. If it's clean locally, CI won't surprise you.
- `cargo fmt --all` before every commit. `rustfmt.toml` carries the project's formatting config.

## Adding a new pass

1. Understand the IR rung your pass targets (Raw=0 through Surface=4) and what `REQUIRES` / `PRODUCES` mean in the capability system — see `crates/disrobe-ir/src/lib.rs`.
2. Create `crates/disrobe-pass-<name>/`. Minimum viable crate: `Cargo.toml` with workspace dep inheritance and a `lib.rs` that registers a `PassDescriptor`.
3. Wire it into `disrobe-cli` under the appropriate subcommand.
4. Emit at least `--emit source` and `--emit report`. Output must be deterministic: same input bytes → same output bytes, no exceptions.
5. Add a test under `tests/integration/` with a self-generated or hash-referenced sample (see `corpus/README.md`).
6. Benchmark with `cargo bench -p disrobe-pass-<name>` and note the baseline in the PR description.

**Grey-zone protectors** (commercial obfuscators with active legal programs — for example VMProtect, Themida, certain DRM stacks): open an issue first. A research review runs before a pass targeting one of these ships. This isn't about discouraging the work; it's about documenting the statutory basis before any code lands.

## Tests

Unit tests live in the crate they test (`#[cfg(test)] mod tests`). Integration tests go in `tests/`. End-to-end tests go in `tests/e2e/` and require sample inputs from `corpus/`.

```
cargo test --workspace                    # unit + integration
cargo test --workspace --test e2e_*       # e2e only
```

## Benchmarks

```
cargo bench --workspace
```

Results are tracked via `divan`. If a PR regresses a benchmark by more than 5%, note it in the description and justify it.

## Filing issues

Use the GitHub issue templates. If something doesn't decompose correctly and you can share the input, attach it. If you can't share the file publicly, hash it with `sha256sum` and note the hash.

## What won't merge

- Any pass that produces non-deterministic output.
- Code with `// TODO`, `// FIXME`, `unimplemented!()`, or `todo!()` in a non-stub position.
- Anything that phones home, writes outside the declared output directory, or modifies the input.
- Attribution of authorship to anyone not listed in `NOTICE`.
