## What

Brief description of what this changes.

## Why

Why is this change needed? Link issues where relevant.

## Testing

How was this tested? New tests added?

## Checklist

- [ ] `cargo fmt --all` clean
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` clean
- [ ] `cargo test --workspace` passes
- [ ] Output is deterministic (same input → same output bytes)
- [ ] No new `unwrap()` / `expect()` in library code without documented invariant
- [ ] Benchmarks not regressed (or regression is justified in the description)
