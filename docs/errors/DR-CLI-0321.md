# DR-CLI-0321

**guard: cannot resolve --root**

a `--root` protected subtree could not be canonicalized.

## Common causes

- nonexistent root dir
- permission denied

## Common fixes

- pass an existing directory to --root

## Source

Emitted from `crates/disrobe-cli/src/cli/guard.rs`.

Look this up at runtime with `disrobe explain DR-CLI-0321`.
